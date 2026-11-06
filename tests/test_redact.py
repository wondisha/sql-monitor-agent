from monitor.agent.redact import redact_payload, redact_sql


def test_redacts_literals_and_emails():
    out = redact_sql("SELECT * FROM users WHERE email = 'bob@corp.com' AND id = 42 AND t1.x > 3.5")
    assert "bob" not in out and "42" not in out and "3.5" not in out
    assert "t1.x" in out and "users" in out


def test_redacts_only_sql_like_keys():
    out = redact_payload({"pid": 123, "query": "SELECT 'secret'", "rows": [{"blocker_last_query": "x = 'y'"}]})
    assert out["pid"] == 123
    assert out["query"] == "SELECT '?'"
    assert out["rows"][0]["blocker_last_query"] == "x = '?'"


def test_identifiers_are_never_redacted():
    out = redact_payload({"query_id": "-8817262", "sample_query_id": "01b2-uuid", "query_hash": "0x1A2B"})
    assert out == {"query_id": "-8817262", "sample_query_id": "01b2-uuid", "query_hash": "0x1A2B"}
