"""Snowflake adapter.

Real-time signals come from INFORMATION_SCHEMA table functions (no lag, need a current database).
Trend/cost signals come from SNOWFLAKE.ACCOUNT_USAGE (up to ~45 min - 3 h lag).
All column names are lower-cased so callers see the same shape as SHOW command output.
"""
from __future__ import annotations

import re

from .base import EngineAdapter, Metric

_QID = re.compile(r"^[0-9a-fA-F-]{36}$")

RECENT_QUERIES = """
SELECT query_id, user_name, role_name, warehouse_name, warehouse_size, execution_status,
       start_time, total_elapsed_time / 1000 AS elapsed_seconds, queued_overload_time / 1000 AS queued_seconds,
       queued_provisioning_time / 1000 AS provisioning_seconds, bytes_scanned,
       error_code, LEFT(error_message, 500) AS error_message,
       LEFT(query_text, 2000) AS query_text
FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY(
    END_TIME_RANGE_START => DATEADD('minute', -%s, CURRENT_TIMESTAMP()), RESULT_LIMIT => 1000))
WHERE 1 = 1
"""
# END_TIME_RANGE_START keeps the table function fast (a plain RESULT_LIMIT scan took >2 min on a real account)
# and still returns queries that are running right now (they have no end time yet).

TOP_QUERIES = """
SELECT query_parameterized_hash AS query_id, ANY_VALUE(warehouse_name) AS warehouse_name, COUNT(*) AS calls,
       ROUND(SUM(total_elapsed_time) / 1000, 1) AS total_seconds, ROUND(AVG(total_elapsed_time) / 1000, 2) AS mean_seconds,
       SUM(bytes_spilled_to_remote_storage) AS remote_spill_bytes,
       ROUND(AVG(partitions_scanned / NULLIF(partitions_total, 0)) * 100, 1) AS avg_pct_partitions_scanned,
       ANY_VALUE(query_id) AS sample_query_id, LEFT(ANY_VALUE(query_text), 2000) AS query_text
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time > DATEADD('hour', -24, CURRENT_TIMESTAMP()) AND query_parameterized_hash IS NOT NULL
GROUP BY query_parameterized_hash
ORDER BY total_seconds DESC
LIMIT %s
"""

WAREHOUSE_LOAD = """
SELECT warehouse_name, MAX(avg_running) AS max_running, MAX(avg_queued_load) AS max_queued_load,
       MAX(avg_queued_provisioning) AS max_queued_provisioning, MAX(avg_blocked) AS max_blocked
FROM TABLE(INFORMATION_SCHEMA.WAREHOUSE_LOAD_HISTORY(DATE_RANGE_START => DATEADD('minute', -15, CURRENT_TIMESTAMP())))
GROUP BY warehouse_name
"""


class SnowflakeAdapter(EngineAdapter):
    engine = "snowflake"
    placeholder = "%s"

    def _connect(self, role: str):
        import snowflake.connector

        cfg = self.target.monitor if role == "monitor" else self.target.executor
        kwargs = dict(
            account=cfg.get("account"), user=cfg.get("user"), role=cfg.get("role"),
            warehouse=cfg.get("warehouse"), database=cfg.get("database"), schema=cfg.get("schema", "PUBLIC"),
            application="sql-monitor-agent", login_timeout=20,
            session_parameters={
                "STATEMENT_TIMEOUT_IN_SECONDS": self.timeout_s,
                "QUERY_TAG": f"sql-monitor-agent:{role}",
            },
        )
        if cfg.get("private_key_path"):
            kwargs["private_key"] = _load_private_key(cfg["private_key_path"], cfg.get("private_key_passphrase"))
        elif cfg.get("password"):
            kwargs["password"] = cfg["password"]
        if cfg.get("authenticator"):
            kwargs["authenticator"] = cfg["authenticator"]
        return snowflake.connector.connect(**kwargs)

    @staticmethod
    def _rows(cur, max_rows: int) -> list[dict]:
        from ..store.db import jsonable
        if cur.description is None:
            return []
        cols = [d[0].lower() for d in cur.description]
        return [jsonable(dict(zip(cols, r))) for r in cur.fetchmany(max_rows)]

    # ---- metrics ---------------------------------------------------------------
    def collect_fast(self) -> list[Metric]:
        m: list[Metric] = []
        q = self.query("""
            SELECT COUNT_IF(execution_status = 'RUNNING') AS running,
                   COUNT_IF(execution_status IN ('QUEUED', 'RESUMING_WAREHOUSE')) AS queued,
                   COUNT_IF(execution_status = 'BLOCKED') AS blocked,
                   COALESCE(MAX(IFF(execution_status = 'RUNNING', DATEDIFF('second', start_time, CURRENT_TIMESTAMP()), 0)), 0) AS longest,
                   COUNT_IF(execution_status LIKE 'FAILED%%') AS failed
            FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY(
                END_TIME_RANGE_START => DATEADD('minute', -15, CURRENT_TIMESTAMP()), RESULT_LIMIT => 1000))""")[0]
        m += [
            Metric("active_sessions", q["running"]),
            Metric("queued_queries", q["queued"]),
            Metric("blocked_sessions", q["blocked"]),
            Metric("longest_query_seconds", q["longest"]),
            Metric("failed_queries_15m", q["failed"]),
        ]
        for r in self.safe(WAREHOUSE_LOAD):
            labels = {"warehouse": r["warehouse_name"]}
            m.append(Metric("warehouse_queued_load", r["max_queued_load"] or 0, labels))
            m.append(Metric("warehouse_running_load", r["max_running"] or 0, labels))
        return m

    def collect_slow(self) -> list[Metric]:
        m: list[Metric] = []
        for r in self.safe("""
                SELECT warehouse_name, SUM(credits_used) AS credits
                FROM TABLE(INFORMATION_SCHEMA.WAREHOUSE_METERING_HISTORY(DATEADD('hour', -1, CURRENT_TIMESTAMP())))
                GROUP BY warehouse_name"""):
            m.append(Metric("warehouse_credits_1h", r["credits"] or 0, {"warehouse": r["warehouse_name"]}))
        # Spill columns exist only in ACCOUNT_USAGE (lags up to ~45 min), so this is a 1-hour window.
        spill = self.safe("""
            SELECT COALESCE(SUM(bytes_spilled_to_remote_storage), 0) / POWER(1024, 3) AS gb
            FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
            WHERE end_time > DATEADD('hour', -1, CURRENT_TIMESTAMP())""")
        if spill:
            m.append(Metric("remote_spill_gb_1h", spill[0]["gb"] or 0))
        tasks = self.safe("""
            SELECT COUNT(*) AS n FROM TABLE(INFORMATION_SCHEMA.TASK_HISTORY(
                SCHEDULED_TIME_RANGE_START => DATEADD('minute', -30, CURRENT_TIMESTAMP()), ERROR_ONLY => TRUE))""")
        if tasks:
            m.append(Metric("task_failures_30m", tasks[0]["n"]))
        logins = self.safe("""
            SELECT COUNT_IF(is_success = 'NO') AS n FROM TABLE(INFORMATION_SCHEMA.LOGIN_HISTORY(
                TIME_RANGE_START => DATEADD('minute', -30, CURRENT_TIMESTAMP())))""")
        if logins:
            m.append(Metric("failed_logins_30m", logins[0]["n"]))
        return m

    # ---- diagnostics -------------------------------------------------------------
    def get_active_sessions(self) -> list[dict]:
        return self.query(RECENT_QUERIES + " AND execution_status IN ('RUNNING','QUEUED','BLOCKED','RESUMING_WAREHOUSE')"
                          " ORDER BY start_time", (60 * 24,))

    def get_blocking_chain(self) -> list[dict]:
        blocked = self.query(RECENT_QUERIES + " AND execution_status = 'BLOCKED' ORDER BY start_time", (60 * 24,))
        locks = self.safe("SHOW LOCKS IN ACCOUNT")
        return [{"blocked_queries": blocked, "locks": locks[: self.max_rows]}]

    def get_top_queries(self, limit: int = 20) -> list[dict]:
        return self.query(TOP_QUERIES, (int(limit),))

    def get_query_plan(self, query_ref: str):
        """query_ref is a query_id. Returns per-operator statistics (the executed plan)."""
        if not _QID.match(query_ref.strip()):
            return {"error": "For Snowflake pass a query_id (UUID) from get_top_queries or get_active_sessions"}
        return self.query("SELECT * FROM TABLE(GET_QUERY_OPERATOR_STATS(%s))", (query_ref.strip(),))

    def get_wait_stats(self) -> list[dict]:
        """Snowflake has no wait stats; warehouse load (running vs queued vs provisioning) is the equivalent."""
        return self.query(WAREHOUSE_LOAD)

    def get_session(self, session_id: str) -> list[dict]:
        if not _QID.match(session_id.strip()):
            return []
        return self.query(RECENT_QUERIES + " AND query_id = %s", (60 * 24, session_id.strip()))

    def extra_tools(self):
        return {
            "recent_queries": lambda minutes=30: self.query(
                RECENT_QUERIES + " ORDER BY total_elapsed_time DESC", (int(minutes),)),
            "warehouses": lambda: self.query("SHOW WAREHOUSES"),
            "warehouse_credits_7d": lambda: self.query("""
                SELECT warehouse_name, DATE_TRUNC('day', start_time) AS day, SUM(credits_used) AS credits
                FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
                WHERE start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                GROUP BY 1, 2 ORDER BY 1, 2"""),
            "failed_tasks": lambda: self.query("""
                SELECT name, database_name, schema_name, state, scheduled_time, error_code, LEFT(error_message, 1000) AS error_message
                FROM TABLE(INFORMATION_SCHEMA.TASK_HISTORY(
                    SCHEDULED_TIME_RANGE_START => DATEADD('hour', -24, CURRENT_TIMESTAMP()), ERROR_ONLY => TRUE))
                ORDER BY scheduled_time DESC LIMIT 50"""),
            "copy_errors": lambda: self.safe("""
                SELECT table_name, pipe_name, last_load_time, status, error_count, LEFT(first_error_message, 500) AS first_error
                FROM SNOWFLAKE.ACCOUNT_USAGE.COPY_HISTORY
                WHERE last_load_time > DATEADD('hour', -24, CURRENT_TIMESTAMP()) AND error_count > 0
                ORDER BY last_load_time DESC LIMIT 50"""),
        }


def _load_private_key(path: str, passphrase: str | None) -> bytes:
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=passphrase.encode() if passphrase else None)
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
