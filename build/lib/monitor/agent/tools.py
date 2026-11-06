"""Read-only tools exposed to the agent, plus their JSON-schema definitions."""
from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..adapters import AdapterRegistry
from ..config import Settings
from ..detector.baseline import BaselineStore
from ..store import Incident, MetricSample, session_scope
from ..store.models import utcnow
from .redact import redact_payload
from .schemas import RCA_TOOL_SCHEMA
from .sql_guard import SQLGuardError, validate_diagnostic

_T = {"type": "string", "description": "Target name from list_targets"}


def _tool(name: str, description: str, props: dict | None = None, required: list[str] | None = None) -> dict:
    return {"name": name, "description": description,
            "input_schema": {"type": "object", "properties": props or {}, "required": required or []}}


class ToolBox:
    def __init__(self, settings: Settings, registry: AdapterRegistry, baseline: BaselineStore | None = None):
        self.settings = settings
        self.registry = registry
        self.baseline = baseline or BaselineStore()
        self.max_chars = int(settings.section("tool_limits").get("max_result_chars", 20000))

    # ---- definitions ---------------------------------------------------------------
    def definitions(self, include_submit: bool) -> list[dict]:
        extra = {name: sorted(a.extra_tools().keys()) for name, a in self.registry.items()}
        extra_desc = "; ".join(f"{t}: {', '.join(n) or '-'}" for t, n in extra.items())
        tools = [
            _tool("list_targets", "List monitored targets with engine type and current health."),
            _tool("get_active_sessions", "Running/non-idle sessions or queries with duration, waits and SQL text.",
                  {"target": _T}, ["target"]),
            _tool("get_blocking_chain", "Who is blocking whom: blocked sessions, their blockers, wait time and the "
                  "blocker's state/last query. Snowflake: BLOCKED queries plus SHOW LOCKS.", {"target": _T}, ["target"]),
            _tool("get_top_queries", "Top queries by total time (pg_stat_statements, performance_schema digests, "
                  "dm_exec_query_stats, Snowflake ACCOUNT_USAGE last 24h).",
                  {"target": _T, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, ["target"]),
            _tool("get_query_plan", "Execution plan. Postgres: query_id or SELECT text (EXPLAIN, not executed). MySQL: "
                  "concrete SELECT text. SQL Server: query_hash 0x... Snowflake: query_id (operator stats).",
                  {"target": _T, "query_ref": {"type": "string"}}, ["target", "query_ref"]),
            _tool("get_wait_stats", "Current wait profile (Snowflake: warehouse running vs queued load).",
                  {"target": _T}, ["target"]),
            _tool("engine_diagnostic", f"Engine-specific read-only diagnostics. Available per target: {extra_desc}.",
                  {"target": _T, "name": {"type": "string"},
                   "minutes": {"type": "integer", "description": "Look-back window where supported"}},
                  ["target", "name"]),
            _tool("run_diagnostic_query", "Run your own read-only SQL against SYSTEM/monitoring views only "
                  "(pg_catalog/pg_stat_*, performance_schema/sys/information_schema, sys.dm_*, "
                  "SNOWFLAKE.ACCOUNT_USAGE / INFORMATION_SCHEMA). Business tables are rejected. Max 200 rows.",
                  {"target": _T, "sql": {"type": "string"}}, ["target", "sql"]),
            _tool("get_metric_history", "Recent samples of a collected metric (e.g. blocking_max_wait_seconds, "
                  "warehouse_queued_load) to see when the problem started.",
                  {"target": _T, "metric": {"type": "string"},
                   "minutes": {"type": "integer", "minimum": 5, "maximum": 10080}}, ["target", "metric"]),
            _tool("compare_to_baseline", "7-day mean/std of a metric vs its latest value.",
                  {"target": _T, "metric": {"type": "string"},
                   "labels_key": {"type": "string", "description": "e.g. warehouse=ETL_WH; empty for unlabeled"}},
                  ["target", "metric"]),
            _tool("search_runbooks", "Keyword search over the team's runbooks.",
                  {"query": {"type": "string"}}, ["query"]),
            _tool("get_similar_incidents", "Past incidents for the same rule/target with their RCA summaries.",
                  {"rule_id": {"type": "string"}, "target": {"type": "string"}}, ["rule_id"]),
        ]
        if include_submit:
            tools.append({"name": "submit_rca", "description": "Submit the final root-cause analysis. Call exactly once.",
                          "input_schema": RCA_TOOL_SCHEMA})
        return tools

    # ---- dispatch ------------------------------------------------------------------
    def call(self, name: str, args: dict) -> tuple[str, bool]:
        """Run a tool. Returns (json_text, is_error)."""
        try:
            fn = getattr(self, f"t_{name}", None)
            if fn is None:
                return json.dumps({"error": f"unknown tool {name}"}), True
            result = fn(**(args or {}))
            return self._serialize(result), False
        except SQLGuardError as e:
            return json.dumps({"error": f"rejected by SQL guard: {e}"}), True
        except TypeError as e:
            return json.dumps({"error": f"bad arguments: {e}"}), True
        except Exception as e:  # noqa: BLE001
            return json.dumps({"error": f"{type(e).__name__}: {str(e)[:800]}"}), True

    def _serialize(self, result: Any) -> str:
        text = json.dumps(redact_payload(result), default=str)
        if len(text) > self.max_chars:
            text = text[: self.max_chars] + f'... [truncated {len(text) - self.max_chars} chars; narrow the query]'
        return text

    # ---- tools ---------------------------------------------------------------------
    def t_list_targets(self):
        return [{"name": n, "engine": a.engine, "health": a.health()} for n, a in self.registry.items()]

    def t_get_active_sessions(self, target: str):
        return self.registry.get(target).get_active_sessions()

    def t_get_blocking_chain(self, target: str):
        return self.registry.get(target).get_blocking_chain()

    def t_get_top_queries(self, target: str, limit: int = 15):
        return self.registry.get(target).get_top_queries(min(int(limit), 50))

    def t_get_query_plan(self, target: str, query_ref: str):
        return self.registry.get(target).get_query_plan(query_ref)

    def t_get_wait_stats(self, target: str):
        return self.registry.get(target).get_wait_stats()

    def t_engine_diagnostic(self, target: str, name: str, minutes: int | None = None):
        tools = self.registry.get(target).extra_tools()
        if name not in tools:
            return {"error": f"unknown diagnostic {name}; available: {sorted(tools)}"}
        fn = tools[name]
        return fn(minutes=int(minutes)) if minutes and "minutes" in fn.__code__.co_varnames else fn()

    def t_run_diagnostic_query(self, target: str, sql: str):
        adapter = self.registry.get(target)
        clean = validate_diagnostic(sql, adapter.engine)
        return adapter.query(clean)

    def t_get_metric_history(self, target: str, metric: str, minutes: int = 120):
        since = utcnow() - timedelta(minutes=int(minutes))
        with session_scope() as s:
            rows = s.execute(
                select(MetricSample.ts, MetricSample.labels_key, MetricSample.value)
                .where(MetricSample.target == target, MetricSample.name == metric, MetricSample.ts >= since)
                .order_by(MetricSample.ts.desc()).limit(300)).all()
        return [{"ts": r.ts.isoformat(timespec="seconds"), "labels": r.labels_key, "value": r.value} for r in rows]

    def t_compare_to_baseline(self, target: str, metric: str, labels_key: str = ""):
        out = self.baseline.describe(target, metric, labels_key)
        with session_scope() as s:
            latest = s.scalars(select(MetricSample.value).where(
                MetricSample.target == target, MetricSample.name == metric, MetricSample.labels_key == labels_key)
                .order_by(MetricSample.ts.desc()).limit(1)).first()
        out["latest"] = latest
        if latest is not None and out.get("std"):
            out["z_score"] = round((latest - out["mean"]) / out["std"], 2)
        return out

    def t_search_runbooks(self, query: str):
        terms = [t for t in re.findall(r"\w+", query.lower()) if len(t) > 2]
        hits = []
        d: Path = self.settings.runbooks_dir
        for f in sorted(d.glob("*.md")) if d.exists() else []:
            text = f.read_text(encoding="utf-8")
            score = sum(text.lower().count(t) for t in terms)
            if score:
                hits.append((score, f.name, text))
        hits.sort(reverse=True)
        return [{"runbook": n, "content": t[:6000]} for _, n, t in hits[:2]] or {"result": "no matching runbook"}

    def t_get_similar_incidents(self, rule_id: str, target: str | None = None):
        with session_scope() as s:
            q = select(Incident).where(Incident.rule_id == rule_id).order_by(Incident.id.desc()).limit(10)
            if target:
                q = q.where(Incident.target == target)
            items = s.scalars(q).all()
            return [{"id": i.id, "target": i.target, "opened_at": i.opened_at.isoformat(timespec="seconds"),
                     "status": i.status, "summary": (i.rca or {}).get("summary"),
                     "root_cause": (i.rca or {}).get("root_cause")} for i in items]
