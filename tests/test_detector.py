from datetime import timedelta

from monitor.adapters.base import Metric
from monitor.detector import Correlator, RuleEngine
from monitor.store import Incident, session_scope

RULES = [
    {"id": "blocking_long", "engines": ["postgres"], "metric": "blocking_max_wait_seconds", "op": ">",
     "threshold": 60, "severity": "P2", "title": "blocked"},
    {"id": "conn_high", "engines": ["postgres"], "metric": "connection_pct", "op": ">", "threshold": 85,
     "for_cycles": 2, "severity": "P2", "title": "connections"},
    {"id": "credits", "engines": ["snowflake"], "type": "anomaly", "metric": "warehouse_credits_1h",
     "z_score": 3, "min_samples": 10, "severity": "P3", "title": "credit spike"},
]


def test_threshold_rule_fires_only_for_matching_engine():
    eng = RuleEngine.from_config(RULES)
    assert len(eng.evaluate("pg1", "postgres", [Metric("blocking_max_wait_seconds", 120)])) == 1
    assert eng.evaluate("pg1", "postgres", [Metric("blocking_max_wait_seconds", 30)]) == []
    assert eng.evaluate("my1", "mysql", [Metric("blocking_max_wait_seconds", 120)]) == []


def test_for_cycles_requires_consecutive_breaches():
    eng = RuleEngine.from_config(RULES)
    m = [Metric("connection_pct", 90)]
    assert eng.evaluate("pg1", "postgres", m) == []
    assert len(eng.evaluate("pg1", "postgres", m)) == 1
    eng.evaluate("pg1", "postgres", [Metric("connection_pct", 10)])  # streak resets
    assert eng.evaluate("pg1", "postgres", m) == []


def test_anomaly_rule_uses_baseline_and_labels():
    eng = RuleEngine.from_config(RULES, baseline=lambda t, m, k: (2.0, 0.5, 100) if k == "warehouse=ETL" else None)
    hot = Metric("warehouse_credits_1h", 5.0, {"warehouse": "ETL"})
    ev = eng.evaluate("sf1", "snowflake", [hot, Metric("warehouse_credits_1h", 50.0, {"warehouse": "OTHER"})])
    assert len(ev) == 1 and ev[0].detail["z_score"] == 6.0
    assert ev[0].dedup_key == "sf1|credits|warehouse=ETL"


def test_correlator_dedups_flaps_and_resolves(db):
    eng = RuleEngine.from_config(RULES)
    corr = Correlator(cooldown_minutes=30, auto_resolve_minutes=15)
    ev = eng.evaluate("pg1", "postgres", [Metric("blocking_max_wait_seconds", 120)])

    with session_scope() as s:
        u1 = corr.process(s, ev)
    with session_scope() as s:
        u2 = corr.process(s, ev)
    assert u1[0].is_new and not u2[0].is_new
    assert u1[0].incident.id == u2[0].incident.id

    with session_scope() as s:  # pretend it stopped firing 20 minutes ago
        inc = s.get(Incident, u1[0].incident.id)
        inc.last_seen_at -= timedelta(minutes=20)
    with session_scope() as s:
        assert corr.resolve_stale(s, healthy_targets=set()) == []      # unhealthy target -> never auto-resolve
    with session_scope() as s:
        assert len(corr.resolve_stale(s, healthy_targets={"pg1"})) == 1

    with session_scope() as s:  # fires again within cooldown -> same incident reopened, not a new page
        u3 = corr.process(s, ev)
    assert not u3[0].is_new and u3[0].incident.id == u1[0].incident.id and u3[0].incident.status == "open"
