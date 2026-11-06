"""The investigator agent: a manual Claude tool-use loop with a tool budget and a structured RCA at the end.

Why a manual loop: we need a hard per-incident tool budget, an audit record of every tool call, and to stop as
soon as submit_rca arrives with a valid RCA.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

import anthropic
from pydantic import ValidationError

from ..actions import Executor
from ..config import Settings
from ..store import Incident, IncidentEvent, session_scope
from ..store.db import audit, jsonable
from .prompts import CHAT_SYSTEM_PROMPT, SYSTEM_PROMPT, incident_prompt
from .schemas import RCA
from .tools import ToolBox

log = logging.getLogger(__name__)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LLMRefusal(RuntimeError):
    pass


class Investigator:
    def __init__(self, settings: Settings, toolbox: ToolBox, executor: Executor,
                 client: Any | None = None, on_rca: Callable[[int], None] | None = None):
        self.settings = settings
        self.cfg = settings.section("llm")
        self.toolbox = toolbox
        self.executor = executor
        self.client = client or anthropic.Anthropic()
        self.on_rca = on_rca

    # ---- Claude call -----------------------------------------------------------------
    def _create(self, system: str, tools: list[dict], messages: list[dict]):
        kwargs = dict(
            model=self.cfg.get("model", "claude-opus-5-5"),
            max_tokens=int(self.cfg.get("max_tokens", 16000)),
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tools,
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": self.cfg.get("effort", "high")},
        )
        if self.cfg.get("server_side_fallback", True):
            # Server-side fallback: if a request is declined by safety classifiers, the API retries it on a
            # suitable model instead of returning a refusal.
            return self.client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
        return self.client.messages.create(**kwargs)

    def _loop(self, system: str, messages: list[dict], include_submit: bool, incident_id: int | None):
        """Run the tool loop. Returns (rca | None, final_text)."""
        tools = self.toolbox.definitions(include_submit=include_submit)
        max_calls = int(self.cfg.get("max_tool_calls", 15))
        max_turns = int(self.cfg.get("max_turns", 20))
        calls, nudged = 0, False

        for _ in range(max_turns):
            resp = self._create(system, tools, messages)
            if resp.stop_reason == "refusal":
                raise LLMRefusal(f"model declined the request: {getattr(resp, 'stop_details', None)}")
            messages.append({"role": "assistant", "content": resp.content})
            if resp.stop_reason == "pause_turn":
                continue
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            text = "".join(b.text for b in resp.content if b.type == "text")

            if not tool_uses:
                if not include_submit:
                    return None, text
                if nudged:
                    raise RuntimeError("agent ended without calling submit_rca")
                nudged = True
                messages.append({"role": "user", "content": "Call submit_rca now with your conclusion."})
                continue

            results, rca = [], None
            for tu in tool_uses:
                if tu.name == "submit_rca":
                    try:
                        rca = RCA.model_validate(tu.input)
                        results.append({"type": "tool_result", "tool_use_id": tu.id, "content": "RCA recorded."})
                    except ValidationError as e:
                        results.append({"type": "tool_result", "tool_use_id": tu.id, "is_error": True,
                                        "content": f"Invalid RCA, fix and resubmit: {e}"[:3000]})
                    continue
                calls += 1
                if calls > max_calls:
                    out, err = json.dumps({"error": "Tool budget exhausted. Call submit_rca now with the evidence "
                                                    "you have; lower confidence if needed."}), True
                else:
                    out, err = self.toolbox.call(tu.name, tu.input)
                self._audit_tool(incident_id, tu.name, tu.input, err)
                block = {"type": "tool_result", "tool_use_id": tu.id, "content": out}
                if err:
                    block["is_error"] = True
                results.append(block)

            if rca is not None:
                return rca, text
            messages.append({"role": "user", "content": results})

        raise RuntimeError(f"agent did not finish within {max_turns} turns")

    def _audit_tool(self, incident_id, name, args, is_error):
        with session_scope() as s:
            audit(s, "agent", "tool_call", detail_incident=incident_id, tool=name, args=jsonable(args), error=is_error)

    # ---- public API --------------------------------------------------------------------
    def investigate(self, incident_id: int) -> RCA | None:
        with session_scope() as s:
            inc = s.get(Incident, incident_id)
            if inc is None:
                raise KeyError(incident_id)
            inc.status, inc.rca_status = "investigating", "running"
            payload = {"incident_id": inc.id, "target": inc.target, "engine": inc.engine, "rule": inc.rule_id,
                       "title": inc.title, "severity": inc.severity, "opened_at": inc.opened_at.isoformat(),
                       "event_count": inc.event_count, "context": inc.context}

        messages = [{"role": "user", "content": incident_prompt(payload)}]
        try:
            rca, _ = self._loop(SYSTEM_PROMPT, messages, include_submit=True, incident_id=incident_id)
        except Exception as e:  # noqa: BLE001
            if "authentication" in str(e).lower():
                e = RuntimeError("No Claude credentials: set ANTHROPIC_API_KEY in .env (or run `ant auth login`)")
                log.warning("incident %s not investigated: %s", incident_id, e)
            else:
                log.exception("investigation of incident %s failed", incident_id)
            with session_scope() as s:
                inc = s.get(Incident, incident_id)
                inc.rca_status, inc.rca_error = "failed", str(e)[:2000]
                if inc.status == "investigating":
                    inc.status = "open"
                s.add(IncidentEvent(incident_id=incident_id, kind="rca", detail={"status": "failed", "error": str(e)[:500]}))
            return None

        with session_scope() as s:
            inc = s.get(Incident, incident_id)
            inc.rca, inc.rca_status, inc.rca_error = rca.model_dump(), "done", None
            if inc.status == "investigating":
                inc.status = "open"
            s.add(IncidentEvent(incident_id=incident_id, kind="rca",
                                detail={"status": "done", "confidence": rca.confidence, "summary": rca.summary}))
            target = inc.target

        for a in rca.proposed_actions:
            self.executor.propose(target=target, action_type=a.type, params=a.params, incident_id=incident_id,
                                  rationale=f"{a.rationale}\nExpected effect: {a.expected_effect}".strip(),
                                  risk=a.risk, actor="agent")
        if self.on_rca:
            try:
                self.on_rca(incident_id)
            except Exception:  # noqa: BLE001
                log.exception("on_rca callback failed")
        return rca

    def chat(self, question: str, history: list[dict] | None = None) -> str:
        messages = list(history or []) + [{"role": "user", "content": question}]
        _, text = self._loop(CHAT_SYSTEM_PROMPT, messages, include_submit=False, incident_id=None)
        return text
