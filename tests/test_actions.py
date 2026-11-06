import pytest

from monitor.actions import ActionError, Executor, render_action
from monitor.adapters import AdapterRegistry
from monitor.store import ActionRecord, AuditLog, session_scope

from .conftest import FakeAdapter, make_settings, pg_target, sf_target


def test_kill_session_renders_per_engine():
    assert render_action("kill_session", "postgres", {"session_id": "42"})[1].sql == "SELECT pg_terminate_backend(42)"
    assert render_action("kill_session", "mysql", {"session_id": 42})[1].sql == "KILL 42"
    assert render_action("kill_session", "mssql", {"session_id": 77})[1].sql == "KILL 77"
    qid = "01b2c3d4-0000-1111-2222-333344445555"
    assert qid in render_action("kill_session", "snowflake", {"query_id": qid})[1].sql


@pytest.mark.parametrize("params", [{"session_id": "42; DROP TABLE x"}, {"session_id": "-1"}, {}])
def test_kill_session_rejects_bad_ids(params):
    with pytest.raises(ActionError):
        render_action("kill_session", "postgres", params)


def test_mssql_refuses_system_sessions():
    with pytest.raises(ActionError):
        render_action("kill_session", "mssql", {"session_id": 12})


def test_resize_warehouse_bounded_by_limit():
    sql = render_action("resize_warehouse", "snowflake", {"warehouse": "ETL_WH", "size": "medium"},
                        {"max_warehouse_size": "LARGE"})[1].sql
    assert sql == "ALTER WAREHOUSE \"ETL_WH\" SET WAREHOUSE_SIZE = 'MEDIUM'"
    with pytest.raises(ActionError):
        render_action("resize_warehouse", "snowflake", {"warehouse": "ETL_WH", "size": "X4LARGE"},
                      {"max_warehouse_size": "LARGE"})
    with pytest.raises(ActionError):
        render_action("resize_warehouse", "snowflake", {"warehouse": 'ETL"; DROP', "size": "SMALL"})


def test_unknown_or_wrong_engine_actions_rejected():
    with pytest.raises(ActionError):
        render_action("drop_table", "postgres", {"table": "x"})
    with pytest.raises(ActionError):
        render_action("resize_warehouse", "postgres", {"warehouse": "x", "size": "SMALL"})


def test_index_is_script_only():
    _, r = render_action("create_index_script", "postgres", {"table": "public.orders", "columns": ["customer_id"]})
    assert not r.executable and "CONCURRENTLY" in r.sql


def _executor(tmp_path, adapter):
    settings = make_settings(tmp_path, targets=[adapter.target])
    reg = AdapterRegistry([])
    reg.register(adapter)
    return Executor(settings, reg)


def test_executor_full_lifecycle(db):
    adapter = FakeAdapter(pg_target(), {"pg_terminate_backend": [{"pg_terminate_backend": True}]})
    ex = _executor(db, adapter)

    rec = ex.propose(target="pg1", action_type="kill_session", params={"session_id": 99}, rationale="blocker")
    assert rec.status == "proposed" and adapter.privileged_sql == []        # nothing runs before approval

    done = ex.approve_and_execute(rec.id, "alice")
    assert done.status == "executed"
    assert adapter.privileged_sql == ["SELECT pg_terminate_backend(%s)"]
    with pytest.raises(ActionError):
        ex.approve_and_execute(rec.id, "alice")                              # no double execution
    with session_scope() as s:
        events = [a.event for a in s.query(AuditLog).order_by(AuditLog.id)]
    assert events == ["action_proposed", "action_approved", "action_executed"]


def test_executor_stores_invalid_proposals_without_running(db):
    adapter = FakeAdapter(sf_target())
    ex = _executor(db, adapter)
    rec = ex.propose(target="sf1", action_type="resize_warehouse", params={"warehouse": "WH", "size": "X6LARGE"})
    assert rec.status == "invalid"
    with session_scope() as s:
        assert s.get(ActionRecord, rec.id).result["error"]


def test_script_only_actions_cannot_be_approved(db):
    adapter = FakeAdapter(pg_target())
    ex = _executor(db, adapter)
    rec = ex.propose(target="pg1", action_type="create_index_script",
                     params={"table": "public.orders", "columns": ["customer_id"]})
    assert rec.status == "script_only"
    with pytest.raises(ActionError):
        ex.approve_and_execute(rec.id, "alice")
    assert adapter.privileged_sql == []
