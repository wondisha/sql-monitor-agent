"""End-to-end: collect -> rule -> incident -> notification -> API approval, with fake adapter and LLM disabled."""
from fastapi.testclient import TestClient

from monitor.adapters.base import Metric
from monitor.api.main import create_api
from monitor.app import App
from monitor.store import Incident, session_scope

from .conftest import FakeAdapter, make_settings, pg_target

RULES = [{"id": "blocking_long", "engines": ["postgres"], "metric": "blocking_max_wait_seconds", "op": ">",
          "threshold": 60, "severity": "P2", "title": "Session blocked"}]


def build(tmp_path, monkeypatch):
    monkeypatch.setenv("MONITOR_USERS", "alice:approver:alice-token-123456,vic:viewer:viewer-token-1234567")
    target = pg_target()
    settings = make_settings(tmp_path, targets=[], rules=RULES, llm={"enabled": False})
    settings.targets.append(target)
    app = App(settings=settings)
    adapter = FakeAdapter(target, {"pg_terminate_backend": [{"ok": True}], "SESSION": [{"pid": 4242}]},
                          metrics=[Metric("blocking_max_wait_seconds", 300)])
    app.registry.register(adapter)
    sent = []
    app.notifier._send = lambda sev, title, body, link, **kw: sent.append(title)
    return app, adapter, sent


def test_collect_opens_one_incident_and_notifies_once(db, monkeypatch):
    app, _, sent = build(db, monkeypatch)
    app.collect("pg1")
    app.collect("pg1")
    with session_scope() as s:
        incs = s.query(Incident).all()
        assert len(incs) == 1 and incs[0].event_count == 2 and incs[0].rca_status == "skipped"
    assert sent == ["[P2] Session blocked"]


def test_collector_failure_raises_incident(db, monkeypatch):
    app, adapter, sent = build(db, monkeypatch)
    adapter.collect_fast = lambda: (_ for _ in ()).throw(ConnectionError("connection refused"))
    app.collect("pg1")
    with session_scope() as s:
        assert s.query(Incident).one().rule_id == "collector_error"
    assert "pg1" not in app.healthy


def test_api_auth_and_approval_flow(db, monkeypatch):
    app, adapter, _ = build(db, monkeypatch)
    app.collect("pg1")
    with session_scope() as s:
        inc_id = s.query(Incident).one().id
    rec = app.executor.propose(target="pg1", action_type="kill_session", params={"session_id": 4242},
                               incident_id=inc_id, rationale="blocker")
    client = TestClient(create_api(app))
    alice = {"Authorization": "Bearer alice-token-123456"}
    vic = {"Authorization": "Bearer viewer-token-1234567"}

    assert client.get("/api/incidents").status_code == 401
    assert client.get("/api/incidents", headers=vic).json()[0]["id"] == inc_id
    assert client.get(f"/api/incidents/{inc_id}", headers=vic).json()["actions"][0]["status"] == "proposed"
    assert client.get(f"/api/actions/{rec.id}/preview", headers=vic).json()["current_state"] == [{"pid": 4242}]
    assert client.post(f"/api/actions/{rec.id}/approve", headers=vic).status_code == 403     # viewers can't approve
    assert adapter.privileged_sql == []

    r = client.post(f"/api/actions/{rec.id}/approve", headers=alice)
    assert r.status_code == 200 and r.json()["status"] == "executed" and r.json()["decided_by"] == "alice"
    assert client.post(f"/api/actions/{rec.id}/approve", headers=alice).status_code == 409   # no double run
    assert adapter.privileged_sql == ["SELECT pg_terminate_backend(%s)"]
    events = [a["event"] for a in client.get("/api/audit", headers=vic).json()]
    assert "action_executed" in events
    assert client.get("/", headers=vic).status_code == 200
