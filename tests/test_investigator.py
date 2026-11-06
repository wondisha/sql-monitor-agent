"""Investigator loop against a scripted fake Claude client (no API calls)."""
from types import SimpleNamespace as NS

from monitor.actions import Executor
from monitor.adapters import AdapterRegistry
from monitor.agent.investigator import Investigator
from monitor.agent.tools import ToolBox
from monitor.store import ActionRecord, AuditLog, Incident, session_scope

from .conftest import FakeAdapter, make_settings, pg_target

RCA = {
    "summary": "Session 4242 holds a row lock in an idle transaction, blocking 3 updates.",
    "root_cause": "Application left a transaction open (idle in transaction) after updating orders.",
    "confidence": "high",
    "impact": "Order updates stalled for 4 minutes.",
    "evidence": [{"finding": "pid 4242 idle in transaction for 260s blocking 3 sessions",
                  "source_tool": "get_blocking_chain"}],
    "proposed_actions": [
        {"type": "kill_session", "params": {"session_id": "4242"}, "rationale": "release the lock", "risk": "medium"},
        {"type": "drop_database", "params": {}, "rationale": "nonsense", "risk": "high"},
    ],
}


def tool_use(id_, name, input_):
    return NS(type="tool_use", id=id_, name=name, input=input_)


class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot: the loop keeps appending
        return self.script.pop(0)


def fake_client(script):
    msgs = FakeMessages(script)
    return NS(messages=msgs, beta=NS(messages=msgs)), msgs


def setup(tmp_path, script):
    adapter = FakeAdapter(pg_target(), {
        "BLOCKING": [{"blocked_pid": 1, "blocker_pid": 4242, "blocker_state": "idle in transaction",
                      "blocker_last_query": "UPDATE orders SET status = 'paid' WHERE id = 991"}],
        "pg_stat_activity": [{"pid": 4242, "state": "idle in transaction"}],
    })
    settings = make_settings(tmp_path, targets=[adapter.target])
    reg = AdapterRegistry([])
    reg.register(adapter)
    client, msgs = fake_client(script)
    ex = Executor(settings, reg)
    inv = Investigator(settings, ToolBox(settings, reg), ex, client=client)
    with session_scope() as s:
        inc = Incident(dedup_key="pg1|blocking_long|", target="pg1", engine="postgres", rule_id="blocking_long",
                       title="Session blocked", severity="P2", context={"latest": {"value": 260}})
        s.add(inc)
        s.flush()
        inc_id = inc.id
    return inv, msgs, adapter, inc_id


def test_investigation_produces_rca_and_validated_proposals(db):
    script = [
        NS(stop_reason="tool_use", content=[
            NS(type="text", text="Checking blocking."),
            tool_use("t1", "get_blocking_chain", {"target": "pg1"}),
            tool_use("t2", "run_diagnostic_query", {"target": "pg1", "sql": "SELECT * FROM orders"}),  # must be refused
        ]),
        NS(stop_reason="tool_use", content=[tool_use("t3", "submit_rca", RCA)]),
    ]
    inv, msgs, adapter, inc_id = setup(db, script)
    rca = inv.investigate(inc_id)

    assert rca.confidence == "high"
    second_call_results = msgs.calls[1]["messages"][-1]["content"]
    by_id = {r["tool_use_id"]: r for r in second_call_results}
    assert "'?'" in by_id["t1"]["content"] and "paid" not in by_id["t1"]["content"]   # literals redacted
    assert by_id["t2"]["is_error"] and "SQL guard" in by_id["t2"]["content"]          # business table refused
    assert adapter.queries == []                                                       # guard stopped it before the DB
    assert msgs.calls[0]["model"] == "claude-opus-5-5"
    assert msgs.calls[0]["thinking"] == {"type": "adaptive"}

    with session_scope() as s:
        inc = s.get(Incident, inc_id)
        assert inc.rca_status == "done" and inc.rca["summary"].startswith("Session 4242")
        acts = {a.action_type: a for a in s.query(ActionRecord).filter_by(incident_id=inc_id)}
        assert acts["kill_session"].status == "proposed"
        assert acts["kill_session"].rendered_sql == "SELECT pg_terminate_backend(4242)"
        assert acts["drop_database"].status == "invalid"                  # not on the allowlist
        assert s.query(AuditLog).filter_by(event="tool_call").count() == 2
    assert adapter.privileged_sql == []                                    # nothing executed without approval


def test_invalid_rca_is_returned_to_model_for_correction(db):
    script = [
        NS(stop_reason="tool_use", content=[tool_use("t1", "submit_rca", {"summary": "x"})]),
        NS(stop_reason="tool_use", content=[tool_use("t2", "submit_rca", RCA)]),
    ]
    inv, msgs, _, inc_id = setup(db, script)
    assert inv.investigate(inc_id) is not None
    err = msgs.calls[1]["messages"][-1]["content"][0]
    assert err["is_error"] and "Invalid RCA" in err["content"]


def test_tool_budget_is_enforced(db):
    many = [tool_use(f"t{i}", "get_blocking_chain", {"target": "pg1"}) for i in range(7)]   # budget is 5
    script = [NS(stop_reason="tool_use", content=many),
              NS(stop_reason="tool_use", content=[tool_use("s", "submit_rca", RCA)])]
    inv, msgs, _, inc_id = setup(db, script)
    inv.investigate(inc_id)
    results = msgs.calls[1]["messages"][-1]["content"]
    assert sum(1 for r in results if "budget exhausted" in r["content"]) == 2


def test_refusal_marks_incident_failed(db):
    script = [NS(stop_reason="refusal", content=[], stop_details={"category": "cyber"})]
    inv, _, _, inc_id = setup(db, script)
    assert inv.investigate(inc_id) is None
    with session_scope() as s:
        inc = s.get(Incident, inc_id)
        assert inc.rca_status == "failed" and "declined" in inc.rca_error and inc.status == "open"
