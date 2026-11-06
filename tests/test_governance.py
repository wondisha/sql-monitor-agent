"""Snowflake inactive-user lifecycle against a scripted fake Snowflake."""
import re
from datetime import timedelta

import pytest

from monitor.adapters import AdapterRegistry
from monitor.governance import SnowflakeUserGovernance
from monitor.governance.snowflake_users import GovernanceError
from monitor.store import AuditLog, GovernanceCase, session_scope
from monitor.store.models import utcnow

from .conftest import FakeAdapter, make_settings, sf_target


def ago(days):
    return (utcnow() - timedelta(days=days)).isoformat()


USERS = [
    {"name": "ALICE", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(5)},
    {"name": "BOB", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(120)},
    {"name": "CAROL", "type": None, "created_on": ago(200), "last_success_login": None},      # never logged in
    {"name": "SVC_ETL", "type": "SERVICE", "created_on": ago(400), "last_success_login": ago(300)},
    {"name": "ADMIN1", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(200)},
    {"name": "KEEPME", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(200)},
    {"name": "GOV_SVC", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(200)},  # executor itself
    {"name": "DAVE", "type": "PERSON", "created_on": ago(400), "last_success_login": ago(200)},     # has queries
]


def make_fake(live_disabled="true"):
    live = {u["name"]: {"name": u["name"], "last_success_login": u["last_success_login"], "disabled": "false"}
            for u in USERS}

    def show_users(sql):
        name = re.search(r"LIKE '(.+)'", sql).group(1)
        return [live[name]] if name in live else []

    def show_grants_of_role(sql):
        return [] if '"BOB_ROLE"' in sql else [{"role": "ANALYST", "granted_to": "USER", "grantee_name": "ALICE"}]

    responses = {
        "ACCOUNT_USAGE.USERS": [{**u, "default_role": None, "disabled": False, "owner": "USERADMIN", "email": None,
                                 "login_name": u["name"]} for u in USERS],
        "GRANTS_TO_ROLES": [{"child": "SECURITYADMIN", "parent": "ADMIN_LEAD"}],     # ADMIN_LEAD inherits SECURITYADMIN
        "GRANTS_TO_USERS": [{"grantee_name": "ADMIN1", "role": "ADMIN_LEAD"}, {"grantee_name": "BOB", "role": "ANALYST"}],
        "QUERY_HISTORY": [{"user_name": "DAVE"}],
        "SHOW USERS LIKE": show_users,
        "SHOW GRANTS TO USER": [{"role": "ANALYST", "granted_to": "USER"}, {"role": "BOB_ROLE", "granted_to": "USER"},
                                {"role": "PUBLIC", "granted_to": "USER"}],
        "DESCRIBE USER": [{"property": "LOGIN_NAME", "value": "BOB"}, {"property": "DEFAULT_ROLE", "value": "ANALYST"}],
        "SHOW GRANTS OF ROLE": show_grants_of_role,
        "ALTER USER": lambda sql: live.__getitem__(re.search(r'"(.+?)"', sql).group(1)).update(
            disabled=live_disabled) or [],
    }
    return FakeAdapter(sf_target(), responses), live


def make_gov(tmp_path, adapter, **overrides):
    cfg = {"enabled": True, "targets": ["sf1"], "dry_run": False, "inactive_days": 90, "grace_period_days": 14,
           "max_users_per_run": 25, "max_flagged_pct": 50, "protected_roles": ["ACCOUNTADMIN", "SECURITYADMIN"],
           "allowlist_users": ["KEEPME"], "roles_never_revoked": ["PUBLIC"], **overrides}
    settings = make_settings(tmp_path, targets=[adapter.target], governance={"snowflake_inactive_users": cfg})
    reg = AdapterRegistry([])
    reg.register(adapter)
    notes = []
    return SnowflakeUserGovernance(settings, reg, notify=lambda t, b: notes.append((t, b))), notes


def test_detection_applies_every_exclusion(db):
    adapter, _ = make_fake()
    gov, _ = make_gov(db, adapter)
    det = gov.detect("sf1")
    assert sorted(c["name"] for c in det["candidates"]) == ["BOB", "CAROL"]
    reasons = {s["name"]: s["reason"] for s in det["skipped"]}
    assert "service" in reasons["SVC_ETL"]
    assert "protected" in reasons["ADMIN1"]         # via role hierarchy, not a direct grant
    assert reasons["KEEPME"] == "allowlisted"
    assert reasons["GOV_SVC"] == "allowlisted"      # never touches its own executor user
    assert "query activity" in reasons["DAVE"]
    assert "ALICE" not in reasons                    # active users are not even considered
    assert "never logged in" in next(c for c in det["candidates"] if c["name"] == "CAROL")["reason"]


def test_full_lifecycle_disable_then_revoke_and_drop(db):
    adapter, _ = make_fake()
    gov, notes = make_gov(db, adapter)
    summary = gov.run("sf1")
    assert summary["flagged"] == 2 and adapter.privileged_sql == []   # flagging changes nothing

    with session_scope() as s:
        bob = s.query(GovernanceCase).filter_by(user_name="BOB").one().id
    assert gov.approve(bob, "alice") == "disabled"
    sql = adapter.privileged_sql
    assert sql.index('SHOW GRANTS TO USER "BOB"') < sql.index('ALTER USER "BOB" SET DISABLED = TRUE')
    with session_scope() as s:
        case = s.get(GovernanceCase, bob)
        assert case.state == "disabled" and case.snapshot["grants"] and set(case.roles) >= {"ANALYST", "BOB_ROLE"}

    gov.run("sf1")                                     # grace period not over -> nothing dropped
    assert not any(q.startswith("DROP USER") for q in adapter.privileged_sql)

    with session_scope() as s:
        s.get(GovernanceCase, bob).disabled_at = utcnow() - timedelta(days=15)
    adapter.privileged_sql.clear()
    summary = gov.run("sf1")
    assert summary["dropped"] == 1
    sql = adapter.privileged_sql
    assert 'REVOKE ROLE "ANALYST" FROM USER "BOB"' in sql and 'REVOKE ROLE "BOB_ROLE" FROM USER "BOB"' in sql
    assert not any('"PUBLIC"' in q for q in sql)       # PUBLIC is never revoked
    assert sql.index('REVOKE ROLE "ANALYST" FROM USER "BOB"') < sql.index('DROP USER "BOB"')
    with session_scope() as s:
        case = s.get(GovernanceCase, bob)
        assert case.state == "dropped" and case.orphaned_roles == ["BOB_ROLE"]
        events = [a.event for a in s.query(AuditLog).order_by(AuditLog.id)]
    assert "governance_snapshot" in events and "governance_dropped" in events
    assert any("Orphaned" in t for t, _ in notes)

    stmts = gov.restore(bob, "alice")
    assert stmts[0].startswith('CREATE USER "BOB"') and 'GRANT ROLE "ANALYST" TO USER "BOB"' in stmts


def test_reenabled_user_is_not_dropped(db):
    adapter, live = make_fake()
    gov, _ = make_gov(db, adapter)
    gov.run("sf1")
    with session_scope() as s:
        bob = s.query(GovernanceCase).filter_by(user_name="BOB").one().id
    gov.approve(bob, "alice")
    live["BOB"]["disabled"] = "false"                  # someone re-enabled BOB during the grace period
    with session_scope() as s:
        s.get(GovernanceCase, bob).disabled_at = utcnow() - timedelta(days=15)
    summary = gov.run("sf1")
    assert summary["cancelled"] == 1
    assert not any(q.startswith(("DROP USER", "REVOKE")) for q in adapter.privileged_sql)


def test_dry_run_changes_nothing(db):
    adapter, _ = make_fake()
    gov, _ = make_gov(db, adapter, dry_run=True)
    gov.run("sf1")
    with session_scope() as s:
        bob = s.query(GovernanceCase).filter_by(user_name="BOB").one().id
    assert gov.approve(bob, "alice") == "dry_run"
    assert all(q.startswith(("SHOW", "DESCRIBE")) for q in adapter.privileged_sql)
    with session_scope() as s:
        assert s.get(GovernanceCase, bob).snapshot["dry_run_plan"] == ['ALTER USER "BOB" SET DISABLED = TRUE']


def test_safety_stop_when_too_many_users_flagged(db):
    adapter, _ = make_fake()
    gov, notes = make_gov(db, adapter, max_flagged_pct=10)
    summary = gov.run("sf1")
    assert "halted" in summary and summary["flagged"] == 0
    with session_scope() as s:
        assert s.query(GovernanceCase).count() == 0
    assert notes and "halted" in notes[0][0]


def test_keep_excludes_user_and_only_flagged_can_be_approved(db):
    adapter, _ = make_fake()
    gov, _ = make_gov(db, adapter)
    gov.run("sf1")
    with session_scope() as s:
        carol = s.query(GovernanceCase).filter_by(user_name="CAROL").one().id
    gov.keep(carol, "alice", "contractor returning in Q1")
    with pytest.raises(GovernanceError):
        gov.approve(carol, "alice")
    assert gov.run("sf1")["flagged"] == 0              # kept users are not re-flagged
