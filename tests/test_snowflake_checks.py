"""Snowflake cost-aware collection, config audit, efficiency checks and the set_warehouse_parameter action."""
import pytest

from monitor.actions import ActionError, render_action
from monitor.adapters.snowflake import NEVER_SUSPENDS, SnowflakeAdapter
from monitor.detector import RuleEngine
from monitor.config import load_settings

from .conftest import ROOT, sf_target

WAREHOUSES = [
    {"name": "ETL_WH", "running": 3, "queued": 2, "auto_suspend": 60, "auto_resume": "true", "resource_monitor": "RM1",
     "max_cluster_count": 1, "started_clusters": 1},
    {"name": "BI_WH", "running": 1, "queued": 0, "auto_suspend": 3600, "auto_resume": "false",
     "resource_monitor": "null", "max_cluster_count": 3, "started_clusters": 3},
    {"name": "NEVER_WH", "running": 0, "queued": 4, "auto_suspend": None, "auto_resume": "true",
     "resource_monitor": "null", "max_cluster_count": 2, "started_clusters": 2},
    {"name": "SYSTEM$STREAMLIT_NOTEBOOK_WH", "running": 9, "queued": 9, "auto_suspend": 60, "auto_resume": "true",
     "resource_monitor": "null", "max_cluster_count": 10, "started_clusters": 0},
]


class FakeSnowflake(SnowflakeAdapter):
    def __init__(self, responses, lock_error=False):
        super().__init__(sf_target(), {})
        self.responses, self.lock_error, self.sql = responses, lock_error, []

    def _connect(self, role):  # pragma: no cover
        raise AssertionError("no connections in tests")

    def query(self, sql, params=None, max_rows=None):
        self.sql.append(sql)
        if "SHOW LOCKS" in sql and self.lock_error:
            raise RuntimeError("needs MONITOR ON ACCOUNT")
        for key, val in self.responses.items():
            if key in sql:
                return val(sql) if callable(val) else val
        return []


BASE = {
    "SHOW WAREHOUSES": WAREHOUSES,
    "SHOW LOCKS": [{"status": "HOLDING"}, {"status": "WAITING"}, {"status": "WAITING"}],
    "IN ACCOUNT": [{"value": "172800"}],
    'IN WAREHOUSE "ETL_WH"': [{"value": "3600"}],
    "SHOW RESOURCE MONITORS": [{"name": "RM1", "credit_quota": "100", "used_credits": "95",
                                "suspend_at": "null", "suspend_immediately_at": "null"}],
}


def metrics(ms):
    return {(m.name, m.labels.get("warehouse") or m.labels.get("monitor", "")): m.value for m in ms}


def test_fast_cycle_uses_only_free_show_commands():
    a = FakeSnowflake(BASE)
    got = metrics(a.collect_fast())
    assert all(s.strip().upper().startswith("SHOW") for s in a.sql)          # never resumes a warehouse
    assert got[("wh_queued_queries", "ETL_WH")] == 2 and got[("queued_queries", "")] == 6
    assert got[("active_sessions", "")] == 4                                  # SYSTEM$ warehouse excluded
    assert got[("blocked_sessions", "")] == 2
    a2 = FakeSnowflake(BASE, lock_error=True)
    assert ("blocked_sessions", "") not in metrics(a2.collect_fast())         # missing grant -> skipped, no crash


def test_config_audit_findings():
    a = FakeSnowflake(BASE)
    got = metrics(a._config_audit())
    assert got[("wh_auto_suspend_seconds", "BI_WH")] == 3600
    assert got[("wh_auto_suspend_seconds", "NEVER_WH")] == NEVER_SUSPENDS
    assert got[("wh_auto_resume_off", "BI_WH")] == 1 and got[("wh_auto_resume_off", "ETL_WH")] == 0
    assert got[("wh_no_resource_monitor", "BI_WH")] == 1 and got[("wh_no_resource_monitor", "ETL_WH")] == 0
    assert got[("wh_statement_timeout_seconds", "ETL_WH")] == 3600            # warehouse-level value
    assert ("wh_statement_timeout_seconds", "BI_WH") not in got               # unreadable: never guessed
    assert got[("wh_settings_unreadable", "BI_WH")] == 1 and got[("wh_settings_unreadable", "ETL_WH")] == 0
    assert got[("wh_multicluster_at_max", "NEVER_WH")] == 1                   # at max and queuing
    assert got[("wh_multicluster_at_max", "BI_WH")] == 0                      # at max but not queuing
    assert got[("rm_used_pct", "RM1")] == 95 and got[("rm_no_suspend", "RM1")] == 1
    assert not any(k[1].startswith("SYSTEM$") for k in got)


def test_heavy_and_daily_metrics_are_cached_between_bursts():
    calls = {"n": 0}

    def history(sql):
        calls["n"] += 1
        return [{"longest": 2400, "failed": 1, "blocked": 0}]

    resp = {**BASE,
            "QUERY_HISTORY(\n": history, "END_TIME_RANGE_START => DATEADD('minute', -30": history,
            "bytes_spilled_to_local_storage) / POWER": [{"warehouse_name": "ETL_WH", "local_gb": 7.5, "remote_gb": 2.0}],
            "percentage_scanned_from_cache": [
                {"warehouse_name": "ETL_WH", "scanned_gb": 50, "cache_pct": 4.0, "poor_pruning": 25},
                {"warehouse_name": "BI_WH", "scanned_gb": 1, "cache_pct": 0.0, "poor_pruning": 0}],
            "credits_attributed_compute_queries": [{"warehouse_name": "BI_WH", "compute": 10, "attributed": 4},
                                                   {"warehouse_name": "TINY_WH", "compute": 0.2, "attributed": 0},
                                                   {"warehouse_name": "COMPUTE_SERVICE_WH_USER_TASKS_POOL_X",
                                                    "compute": 9, "attributed": 0}],
            "METERING_DAILY_HISTORY": [{"compute": 20, "cloud": 3}]}
    a = FakeSnowflake(resp)
    first = metrics(a.collect_slow())
    second = metrics(a.collect_slow())
    assert calls["n"] == 1                                                    # heavy burst ran once, then cached
    assert first == second                                                    # cached values re-emitted
    assert first[("longest_query_seconds", "")] == 2400
    assert first[("wh_local_spill_gb_1h", "ETL_WH")] == 7.5 and first[("wh_remote_spill_gb_1h", "ETL_WH")] == 2.0
    assert first[("wh_cache_hit_pct_24h", "ETL_WH")] == 4.0
    assert ("wh_cache_hit_pct_24h", "BI_WH") not in first                     # under 10 GB scanned: skipped
    assert first[("wh_poor_pruning_queries_24h", "ETL_WH")] == 25
    assert first[("wh_idle_credit_pct_24h", "BI_WH")] == 60.0
    assert ("wh_idle_credit_pct_24h", "TINY_WH") not in first                 # under 1 credit: skipped
    assert not any(k[1].startswith("COMPUTE_SERVICE_WH_") for k in first)    # Snowflake-managed pool: excluded
    assert first[("cloud_services_pct_1d", "")] == 15.0


def test_rules_fire_on_the_new_metrics():
    rules = [r for r in load_settings(ROOT / "config" / "settings.yaml").rules if r["engines"] == ["snowflake"]]
    eng = RuleEngine.from_config(rules)
    a = FakeSnowflake(BASE)
    fired = {(e.rule.id, e.metric.labels.get("warehouse") or e.metric.labels.get("monitor", ""))
             for e in eng.evaluate("sf1", "snowflake", a._config_audit())}
    assert {("sf_auto_suspend_high", "BI_WH"), ("sf_auto_suspend_high", "NEVER_WH"), ("sf_auto_resume_off", "BI_WH"),
            ("sf_no_resource_monitor", "BI_WH"), ("sf_settings_unreadable", "BI_WH"),
            ("sf_resource_monitor_near_quota", "RM1"), ("sf_resource_monitor_no_suspend", "RM1")} <= fired
    assert ("sf_auto_suspend_high", "ETL_WH") not in fired and ("sf_no_resource_monitor", "ETL_WH") not in fired
    assert ("sf_statement_timeout_default", "BI_WH") not in fired             # no false alarm when unreadable


def test_set_warehouse_parameter_action():
    ok = render_action("set_warehouse_parameter", "snowflake",
                       {"warehouse": "BI_WH", "parameter": "auto_suspend", "value": "300"})[1].sql
    assert ok == 'ALTER WAREHOUSE "BI_WH" SET AUTO_SUSPEND = 300'
    assert render_action("set_warehouse_parameter", "snowflake",
                         {"warehouse": "BI_WH", "parameter": "SCALING_POLICY", "value": "economy"})[1].sql \
        == "ALTER WAREHOUSE \"BI_WH\" SET SCALING_POLICY = 'ECONOMY'"
    for bad in ({"parameter": "AUTO_SUSPEND", "value": "5"},          # below minimum
                {"parameter": "AUTO_RESUME", "value": "FALSE"},        # never automated
                {"parameter": "WAREHOUSE_SIZE", "value": "X6LARGE"},   # not on the list (resize has its own cap)
                {"parameter": "AUTO_SUSPEND", "value": "300; DROP DATABASE X"}):
        with pytest.raises(ActionError):
            render_action("set_warehouse_parameter", "snowflake", {"warehouse": "BI_WH", **bad})
