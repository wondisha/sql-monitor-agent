from __future__ import annotations

from .base import EngineAdapter, Metric

ACTIVE_SESSIONS = """
SELECT ID AS id, USER AS user, HOST AS host, DB AS db, COMMAND AS command, TIME AS seconds,
       STATE AS state, LEFT(INFO, 2000) AS query
FROM information_schema.PROCESSLIST
WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump') AND ID <> CONNECTION_ID()
ORDER BY TIME DESC
"""

BLOCKING = """
SELECT wait_started, wait_age_secs, locked_table, locked_index, locked_type,
       waiting_pid, LEFT(waiting_query, 2000) AS waiting_query, waiting_lock_mode,
       blocking_pid, LEFT(blocking_query, 2000) AS blocking_query, blocking_lock_mode,
       blocking_trx_age, blocking_trx_rows_locked, blocking_trx_rows_modified,
       sql_kill_blocking_connection
FROM sys.innodb_lock_waits ORDER BY wait_age_secs DESC
"""

TOP_QUERIES = """
SELECT DIGEST AS query_id, SCHEMA_NAME AS db, COUNT_STAR AS calls,
       ROUND(SUM_TIMER_WAIT / 1e9, 1) AS total_ms, ROUND(AVG_TIMER_WAIT / 1e9, 2) AS mean_ms,
       SUM_ROWS_EXAMINED AS rows_examined, SUM_ROWS_SENT AS rows_sent,
       SUM_NO_INDEX_USED AS no_index_used, SUM_CREATED_TMP_DISK_TABLES AS tmp_disk_tables,
       LEFT(DIGEST_TEXT, 2000) AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE DIGEST IS NOT NULL
ORDER BY SUM_TIMER_WAIT DESC LIMIT %s
"""

WAITS = """
SELECT EVENT_NAME AS event, COUNT_STAR AS count, ROUND(SUM_TIMER_WAIT / 1e12, 2) AS total_seconds
FROM performance_schema.events_waits_summary_global_by_event_name
WHERE COUNT_STAR > 0 AND EVENT_NAME <> 'idle'
ORDER BY SUM_TIMER_WAIT DESC LIMIT 25
"""


class MySQLAdapter(EngineAdapter):
    engine = "mysql"
    placeholder = "%s"

    def _connect(self, role: str):
        import pymysql

        cfg = self.target.monitor if role == "monitor" else self.target.executor
        conn = pymysql.connect(
            host=cfg.get("host"), port=int(cfg.get("port", 3306)), user=cfg.get("user"),
            password=cfg.get("password"), database=cfg.get("database"), autocommit=True,
            connect_timeout=10, read_timeout=self.timeout_s + 5, charset="utf8mb4",
        )
        if role == "monitor":
            with conn.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
                cur.execute(f"SET SESSION max_execution_time = {self.timeout_s * 1000}")
        return conn

    def _status(self, *names: str) -> dict[str, float]:
        marks = ",".join(["%s"] * len(names))
        rows = self.query(
            f"SELECT VARIABLE_NAME AS k, VARIABLE_VALUE AS v FROM performance_schema.global_status "
            f"WHERE VARIABLE_NAME IN ({marks})", names)
        return {r["k"]: float(r["v"]) for r in rows}

    def collect_fast(self) -> list[Metric]:
        m: list[Metric] = []
        st = self._status("Threads_connected", "Threads_running")
        max_conn = self.scalar(self.query("SELECT @@max_connections"), 1) or 1
        conns = st.get("Threads_connected", 0)
        m += [
            Metric("connections", conns),
            Metric("active_sessions", st.get("Threads_running", 0)),
            Metric("connection_pct", 100.0 * conns / max_conn),
        ]
        longest = self.query("""SELECT COALESCE(MAX(TIME), 0) FROM information_schema.PROCESSLIST
                                WHERE COMMAND = 'Query' AND ID <> CONNECTION_ID()""")
        m.append(Metric("longest_query_seconds", self.scalar(longest, 0)))
        trx = self.query("""SELECT COALESCE(MAX(TIMESTAMPDIFF(SECOND, trx_started, NOW())), 0)
                            FROM information_schema.innodb_trx""")
        m.append(Metric("longest_trx_seconds", self.scalar(trx, 0)))

        blk = self.safe("SELECT COUNT(*) AS n, COALESCE(MAX(wait_age_secs), 0) AS w FROM sys.innodb_lock_waits")
        if blk:
            m += [Metric("blocked_sessions", blk[0]["n"]), Metric("blocking_max_wait_seconds", blk[0]["w"])]

        rep = self.safe("SHOW REPLICA STATUS") or self.safe("SHOW SLAVE STATUS")
        if rep:
            lag = rep[0].get("Seconds_Behind_Source", rep[0].get("Seconds_Behind_Master"))
            # NULL lag means the replication SQL/IO thread is stopped - treat as very large.
            m.append(Metric("replication_lag_seconds", float(lag) if lag is not None else 1e9))

        dl = self.safe("SELECT COUNT FROM information_schema.INNODB_METRICS WHERE NAME = 'lock_deadlocks'")
        d = self.delta("deadlocks", self.scalar(dl)) if dl else None
        if d is not None:
            m.append(Metric("deadlocks_delta", d))
        return m

    def get_active_sessions(self) -> list[dict]:
        return self.query(ACTIVE_SESSIONS)

    def get_blocking_chain(self) -> list[dict]:
        return self.query(BLOCKING)

    def get_top_queries(self, limit: int = 20) -> list[dict]:
        return self.query(TOP_QUERIES, (int(limit),))

    def get_query_plan(self, query_ref: str):
        """query_ref must be a concrete SELECT (digest text contains '?' placeholders and can't be explained)."""
        from ..agent.sql_guard import assert_select_only
        assert_select_only(query_ref, "mysql")
        return self.query(f"EXPLAIN FORMAT=JSON {query_ref}")

    def get_wait_stats(self) -> list[dict]:
        return self.query(WAITS)

    def get_session(self, session_id: str) -> list[dict]:
        return self.query("""SELECT ID AS id, USER AS user, HOST AS host, DB AS db, COMMAND AS command,
                             TIME AS seconds, STATE AS state, LEFT(INFO, 1000) AS query
                             FROM information_schema.PROCESSLIST WHERE ID = %s""", (int(session_id),))

    def extra_tools(self):
        return {
            "innodb_transactions": lambda: self.query("""
                SELECT trx_id, trx_state, trx_started, TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS age_seconds,
                       trx_mysql_thread_id AS pid, trx_rows_locked, trx_rows_modified, LEFT(trx_query, 1000) AS query
                FROM information_schema.innodb_trx ORDER BY trx_started LIMIT 50"""),
            "tables_without_index_use": lambda: self.safe("""
                SELECT * FROM sys.schema_tables_with_full_table_scans LIMIT 25"""),
        }
