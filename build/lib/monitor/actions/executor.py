"""Human-in-the-loop executor: propose -> preview -> approve/reject -> execute, every step audited."""
from __future__ import annotations

import logging

from ..adapters import AdapterRegistry
from ..config import Settings
from ..store import ActionRecord, IncidentEvent, session_scope
from ..store.db import audit, jsonable
from ..store.models import utcnow
from .allowlist import ActionError, render_action

log = logging.getLogger(__name__)


class Executor:
    def __init__(self, settings: Settings, registry: AdapterRegistry):
        self.settings = settings
        self.registry = registry

    def propose(self, *, target: str, action_type: str, params: dict, incident_id: int | None = None,
                rationale: str = "", risk: str | None = None, rollback: str = "", actor: str = "agent") -> ActionRecord:
        t = self.settings.target(target)
        with session_scope() as s:
            try:
                spec, rendered = render_action(action_type, t.engine, params, t.limits)
                status = "proposed" if rendered.executable else "script_only"
                rec = ActionRecord(
                    incident_id=incident_id, target=target, action_type=action_type, params=jsonable(params),
                    rendered_sql=rendered.sql, risk=risk or spec.risk, rationale=rationale,
                    rollback=rollback or spec.rollback, status=status)
            except ActionError as e:
                rec = ActionRecord(incident_id=incident_id, target=target, action_type=action_type,
                                   params=jsonable(params), rationale=rationale, status="invalid",
                                   result={"error": str(e)})
            s.add(rec)
            s.flush()
            audit(s, actor, "action_proposed", target, action_id=rec.id, type=action_type, status=rec.status,
                  sql=rec.rendered_sql, params=params)
            if incident_id:
                s.add(IncidentEvent(incident_id=incident_id, kind="action",
                                    detail={"action_id": rec.id, "type": action_type, "status": rec.status}))
            return rec

    def preview(self, action_id: int) -> dict:
        with session_scope() as s:
            rec = s.get(ActionRecord, action_id)
            if rec is None:
                raise KeyError(action_id)
            out = {"id": rec.id, "sql": rec.rendered_sql, "status": rec.status, "risk": rec.risk,
                   "rollback": rec.rollback, "target": rec.target}
            sid = rec.params.get("session_id") or rec.params.get("query_id")
        if sid is not None:
            try:
                out["current_state"] = self.registry.get(out["target"]).get_session(str(sid))
                if not out["current_state"]:
                    out["note"] = "Session/query no longer exists - the action may be unnecessary."
            except Exception as e:  # noqa: BLE001
                out["current_state_error"] = str(e)[:300]
        return out

    def reject(self, action_id: int, approver: str, reason: str = "") -> ActionRecord:
        with session_scope() as s:
            rec = s.get(ActionRecord, action_id)
            if rec is None or rec.status != "proposed":
                raise ActionError("only proposed actions can be rejected")
            rec.status, rec.decided_by, rec.decided_at = "rejected", approver, utcnow()
            rec.result = {"reason": reason}
            audit(s, approver, "action_rejected", rec.target, action_id=rec.id, reason=reason)
            return rec

    def approve_and_execute(self, action_id: int, approver: str) -> ActionRecord:
        with session_scope() as s:
            rec = s.get(ActionRecord, action_id)
            if rec is None:
                raise KeyError(action_id)
            if rec.status != "proposed":
                raise ActionError(f"action {action_id} is {rec.status}, not proposed")
            rec.status, rec.decided_by, rec.decided_at = "approved", approver, utcnow()
            audit(s, approver, "action_approved", rec.target, action_id=rec.id, sql=rec.rendered_sql)
            target, action_type, params = rec.target, rec.action_type, dict(rec.params)
            incident_id = rec.incident_id

        t = self.settings.target(target)
        status, result = "failed", {}
        try:
            # Re-render from stored params - never trust previously stored SQL text.
            _, rendered = render_action(action_type, t.engine, params, t.limits)
            if not rendered.executable:
                raise ActionError("script-only actions are never executed automatically")
            rows = self.registry.get(target).execute_privileged(rendered.bind_sql, rendered.params)
            status, result = "executed", {"rows": rows[:20]}
        except Exception as e:  # noqa: BLE001
            log.exception("action %s failed", action_id)
            result = {"error": str(e)[:1000]}

        with session_scope() as s:
            rec = s.get(ActionRecord, action_id)
            rec.status, rec.executed_at, rec.result = status, utcnow(), jsonable(result)
            audit(s, approver, f"action_{status}", target, action_id=action_id, result=result)
            if incident_id:
                s.add(IncidentEvent(incident_id=incident_id, kind="action",
                                    detail={"action_id": action_id, "status": status, "by": approver}))
            return rec
