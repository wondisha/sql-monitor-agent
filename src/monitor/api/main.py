"""REST API + dashboard. Auth: `Authorization: Bearer <token>` from MONITOR_USERS (name:role:token,...)."""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from .. import targets_store
from ..actions.allowlist import ActionError
from ..adapters import build_adapter
from ..app import App
from ..governance.snowflake_users import GovernanceError
from ..store import ActionRecord, AuditLog, GovernanceCase, Incident, IncidentEvent, MetricSample, session_scope
from ..store.db import audit
from ..store.models import utcnow

STATIC = Path(__file__).parent / "static"


@dataclass
class User:
    name: str
    role: str


def _load_users() -> dict[str, User]:
    users = {}
    for item in filter(None, (os.environ.get("MONITOR_USERS") or "").split(",")):
        parts = item.strip().split(":", 2)
        if len(parts) == 3 and parts[1] in ("viewer", "approver") and len(parts[2]) >= 16:
            users[parts[2]] = User(parts[0], parts[1])
    return users


def _row(obj, *fields):
    out = {}
    for f in fields:
        v = getattr(obj, f)
        out[f] = v.isoformat(timespec="seconds") if hasattr(v, "isoformat") else v
    return out


INC_FIELDS = ("id", "target", "engine", "rule_id", "title", "severity", "status", "opened_at", "last_seen_at",
              "resolved_at", "event_count", "rca_status")
ACT_FIELDS = ("id", "incident_id", "target", "action_type", "params", "rendered_sql", "risk", "rationale", "rollback",
              "status", "created_at", "decided_by", "decided_at", "executed_at", "result")
GOV_FIELDS = ("id", "target", "user_name", "state", "reason", "last_success_login", "user_created_on", "roles",
              "flagged_at", "decided_by", "decided_at", "disabled_at", "dropped_at", "keep_until", "orphaned_roles",
              "error")


class ChatIn(BaseModel):
    question: str


class NoteIn(BaseModel):
    reason: str = ""


def create_api(app: App) -> FastAPI:
    api = FastAPI(title="SQL Monitor Agent", version="0.1.0")
    users = _load_users()
    if not users:
        raise RuntimeError("Set MONITOR_USERS=name:role:token (token >= 16 chars) before starting the API")

    def current_user(request: Request) -> User:
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        for t, u in users.items():
            if token and hmac.compare_digest(t, token):
                return u
        raise HTTPException(401, "invalid or missing token")

    def approver(user: User = Depends(current_user)) -> User:
        if user.role != "approver":
            raise HTTPException(403, "approver role required")
        return user

    @api.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @api.get("/api/me")
    def me(user: User = Depends(current_user)):
        return {"name": user.name, "role": user.role}

    @api.get("/api/targets")
    def targets(user: User = Depends(current_user)):
        out = []
        with session_scope() as s:
            for name, a in app.registry.items():
                last = s.scalars(select(func.max(MetricSample.ts)).where(MetricSample.target == name)).first()
                latest = {}
                if last:
                    for m in s.scalars(select(MetricSample).where(MetricSample.target == name, MetricSample.ts == last)):
                        latest[m.name + (f"[{m.labels_key}]" if m.labels_key else "")] = round(m.value, 2)
                open_n = s.scalar(select(func.count(Incident.id)).where(
                    Incident.target == name, Incident.status.in_(("open", "investigating"))))
                out.append({"name": name, "engine": a.engine, "healthy": name in app.healthy,
                            "source": a.target.source, "has_executor": bool(a.target.executor.get("user")),
                            "last_sample": last.isoformat(timespec="seconds") if last else None,
                            "open_incidents": open_n, "latest": latest})
        return out

    # ---- add / test / remove servers from the dashboard ----------------------------------
    @api.get("/api/targets/schema")
    def target_schema(user: User = Depends(current_user)):
        return targets_store.schema()

    def _test(target) -> dict:
        adapter = build_adapter(target, app.settings.section("tool_limits"))
        result = {"monitor": adapter.health()}
        if result["monitor"]["ok"]:
            try:
                metrics = adapter.collect_fast() + adapter.collect_slow()
                result["monitor"]["metrics_collected"] = len(metrics)
            except Exception as e:  # noqa: BLE001 - connected, but missing permissions for some views
                result["monitor"] = {"ok": False, "error": f"connected, but collection failed (check grants): "
                                                           f"{str(e)[:400]}"}
        adapter.close()
        if target.executor.get("user"):
            try:
                with adapter.privileged() as run:
                    run("SELECT 1")
                result["executor"] = {"ok": True}
            except Exception as e:  # noqa: BLE001
                result["executor"] = {"ok": False, "error": str(e)[:500]}
        else:
            result["executor"] = {"ok": None, "note": "no executor login: approved actions will not run"}
        return result

    @api.post("/api/targets/test")
    def target_test(form: dict = Body(...), user: User = Depends(approver)):
        try:
            target, _, _ = targets_store.build(app.settings, form, for_test=True)
        except targets_store.TargetFormError as e:
            raise HTTPException(400, str(e)) from None
        return _test(target)

    @api.post("/api/targets")
    def target_add(form: dict = Body(...), user: User = Depends(approver)):
        try:
            target, entry, secrets = targets_store.build(app.settings, form)
        except targets_store.TargetFormError as e:
            raise HTTPException(400, str(e)) from None
        result = _test(target)
        if not result["monitor"]["ok"] and not form.get("save_anyway"):
            raise HTTPException(409, "monitor login test failed: " + result["monitor"].get("error", ""))
        targets_store.save(app.settings, entry, secrets)
        app.add_target(target)
        with session_scope() as s:
            audit(s, user.name, "target_added", target.name, engine=target.engine,
                  has_executor=bool(target.executor.get("user")))
        return {"added": target.name, "test": result}

    @api.delete("/api/targets/{name}")
    def target_remove(name: str, user: User = Depends(approver)):
        try:
            targets_store.delete(app.settings, name)
        except targets_store.TargetFormError as e:
            raise HTTPException(409, str(e)) from None
        app.remove_target(name)
        with session_scope() as s:
            audit(s, user.name, "target_removed", name)
        return {"removed": name}

    @api.get("/api/incidents")
    def incidents(status: str | None = None, limit: int = 100, user: User = Depends(current_user)):
        with session_scope() as s:
            q = select(Incident).order_by(Incident.id.desc()).limit(min(limit, 500))
            if status == "active":
                q = q.where(Incident.status.in_(("open", "investigating")))
            elif status:
                q = q.where(Incident.status == status)
            return [{**_row(i, *INC_FIELDS), "summary": (i.rca or {}).get("summary")} for i in s.scalars(q)]

    @api.get("/api/incidents/{incident_id}")
    def incident(incident_id: int, user: User = Depends(current_user)):
        with session_scope() as s:
            i = s.get(Incident, incident_id)
            if i is None:
                raise HTTPException(404)
            events = s.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
                               .order_by(IncidentEvent.id)).all()
            actions = s.scalars(select(ActionRecord).where(ActionRecord.incident_id == incident_id)
                                .order_by(ActionRecord.id)).all()
            return {**_row(i, *INC_FIELDS), "context": i.context, "rca": i.rca, "rca_error": i.rca_error,
                    "events": [_row(e, "ts", "kind", "detail") for e in events],
                    "actions": [_row(a, *ACT_FIELDS) for a in actions]}

    @api.post("/api/incidents/{incident_id}/investigate")
    def investigate(incident_id: int, user: User = Depends(approver)):
        with session_scope() as s:
            if s.get(Incident, incident_id) is None:
                raise HTTPException(404)
            audit(s, user.name, "investigation_requested", incident_id=incident_id)
        app.submit_investigation(incident_id)
        return {"queued": True}

    @api.post("/api/incidents/{incident_id}/resolve")
    def resolve(incident_id: int, body: NoteIn, user: User = Depends(approver)):
        with session_scope() as s:
            i = s.get(Incident, incident_id)
            if i is None:
                raise HTTPException(404)
            i.status, i.resolved_at = "resolved", utcnow()
            s.add(IncidentEvent(incident_id=i.id, kind="resolved", detail={"by": user.name, "note": body.reason}))
            audit(s, user.name, "incident_resolved", i.target, incident_id=i.id, note=body.reason)
        return {"ok": True}

    @api.get("/api/actions")
    def actions(status: str | None = "proposed", user: User = Depends(current_user)):
        with session_scope() as s:
            q = select(ActionRecord).order_by(ActionRecord.id.desc()).limit(200)
            if status:
                q = q.where(ActionRecord.status == status)
            return [_row(a, *ACT_FIELDS) for a in s.scalars(q)]

    @api.get("/api/actions/{action_id}/preview")
    def preview(action_id: int, user: User = Depends(current_user)):
        try:
            return app.executor.preview(action_id)
        except KeyError:
            raise HTTPException(404) from None

    @api.post("/api/actions/{action_id}/approve")
    def approve(action_id: int, user: User = Depends(approver)):
        try:
            rec = app.executor.approve_and_execute(action_id, user.name)
        except KeyError:
            raise HTTPException(404) from None
        except ActionError as e:
            raise HTTPException(409, str(e)) from None
        return _row(rec, *ACT_FIELDS)

    @api.post("/api/actions/{action_id}/reject")
    def reject(action_id: int, body: NoteIn, user: User = Depends(approver)):
        try:
            return _row(app.executor.reject(action_id, user.name, body.reason), *ACT_FIELDS)
        except ActionError as e:
            raise HTTPException(409, str(e)) from None

    @api.get("/api/governance/cases")
    def gov_cases(state: str | None = None, user: User = Depends(current_user)):
        with session_scope() as s:
            q = select(GovernanceCase).order_by(GovernanceCase.id.desc()).limit(500)
            if state:
                q = q.where(GovernanceCase.state == state)
            return {"dry_run": app.governance.dry_run, "cases": [_row(c, *GOV_FIELDS) for c in s.scalars(q)]}

    def _gov(fn, *args):
        try:
            return {"result": fn(*args)}
        except GovernanceError as e:
            raise HTTPException(409, str(e)) from None

    @api.post("/api/governance/cases/{case_id}/approve")
    def gov_approve(case_id: int, user: User = Depends(approver)):
        return _gov(app.governance.approve, case_id, user.name)

    @api.post("/api/governance/cases/{case_id}/keep")
    def gov_keep(case_id: int, body: NoteIn, user: User = Depends(approver)):
        return _gov(app.governance.keep, case_id, user.name, body.reason)

    @api.post("/api/governance/cases/{case_id}/restore")
    def gov_restore(case_id: int, user: User = Depends(approver)):
        return _gov(app.governance.restore, case_id, user.name)

    @api.post("/api/governance/run")
    def gov_run(user: User = Depends(approver)):
        return app.run_governance(actor=user.name)

    @api.get("/api/audit")
    def audit_log(limit: int = 200, user: User = Depends(current_user)):
        with session_scope() as s:
            rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 1000)))
            return [_row(r, "id", "ts", "actor", "target", "event", "detail") for r in rows]

    @api.post("/api/chat")
    def chat(body: ChatIn, user: User = Depends(current_user)):
        if not app.settings.section("llm").get("enabled", True):
            raise HTTPException(400, "LLM is disabled in settings")
        with session_scope() as s:
            audit(s, user.name, "chat", question=body.question[:2000])
        try:
            return {"answer": app.investigator.chat(body.question)}
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"agent error: {str(e)[:500]}") from None

    return api
