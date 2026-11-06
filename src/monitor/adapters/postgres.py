from __future__ import annotations

from .base import EngineAdapter, Metric

ACTIVE_SESSIONS = """
SELECT pid, usename, datname, application_name, client_addr::text AS client_addr, state,
       wait_event_type, wait_event, backend_type,
       EXTRACT(EPOCH FROM now() - xact_start)  AS xact_seconds,
       EXTRACT(EPOCH FROM now() - query_start) AS query_seconds,
       left(query, 2000) AS query
FROM pg_stat_activity
WHERE pid <> pg_backend_pid() AND backend_type = 'client backend' AND state <> 'idle'
ORDER BY query_start NULLS LAST
"""

BLOCKING = """
SELECT a.pid AS blocked_pid, pg_blocking_pids(a.pid) AS blocked_by, a.usename, a.datname,
       a.wait_event_type, a.wait_event,
       EXTRACT(EPOCH FROM now() - a.query_start) AS wait_seconds,
       left(a.query, 2000) AS blocked_query,
       b.pid AS blocker_pid, b.usename AS blocker_user, b.state AS blocker_state,
       EXTRACT(EPOCH FROM now() - b.xact_start) AS blocker_xact_seconds,
       left(b.query, 2000) AS blocker_last_query
FROM pg_stat_activity a
JOIN LATERAL unnest(pg_blocking_pids(a.pid)) AS bp(pid) ON true
JOIN pg_stat_activity b ON b.pid = bp.pid
ORDER BY wait_seconds DESC
"""

TOP_QUERIES = """
SELECT queryid::text AS query_id, calls, round(total_exec_time::numeric, 1) AS total_ms,
       round(mean_exec_time::numeric, 2) AS mean_ms, rows,
       shared_blks_hit, shared_blks_read, temp_blks_written, left(query, 2000) AS query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT %s
"""

WAITS = """
SELECT wait_event_type, wait_event, state, count(*) AS sessions
FROM pg_stat_activity
WHERE wait_event IS NOT NULL AND backend_type = 'client backend'
GROUP BY 1, 2, 3 ORDER BY sessions DESC
"""


class PostgresAdapter(EngineAdapter):
    engine = "postgres"
    placeholder = "%s"

    def _connect(self, role: str):
        import psycopg

        cfg = dict(self.target.monitor if role == "monitor" else self.target.executor)
        opts = f"-c statement_timeout={self.timeout_s * 1000} -c application_name=sql-monitor-agent"
        if role == "monitor":
            opts += " -c default_transaction_read_only=on"
        return psycopg.connect(
            host=cfg.get("host"), port=cfg.get("port", 5432), dbname=cfg.get("dbname"),
            user=cfg.get("user"), password=cfg.get("password"), sslmode=cfg.get("sslmode", "prefer"),
            options=opts, autocommit=True, connect_timeout=10,
        )

    def collect_fast(self) -> list[Metric]:
        m: list[Metric] = []
        row = self.query("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE state = 'active') AS active,
                   current_setting('max_connections')::int AS max_conn,
                   COALESCE(max(EXTRACT(EPOCH FROM now() - query_start))
                       FILTER (WHERE state = 'active' AND backend_type = 'client backend'
                               AND pid <> pg_backend_pid()), 0) AS longest,
                   COALESCE(max(EXTRACT(EPOCH FROM now() - state_change))
                       FILTER (WHERE state LIKE 'idle in transaction%%'), 0) AS idle_txn
            FROM pg_stat_activity""")[0]
        m += [
            Metric("connections", row["total"]),
            Metric("active_sessions", row["active"]),
            Metric("connection_pct", 100.0 * row["total"] / max(row["max_conn"], 1)),
            Metric("longest_query_seconds", row["longest"]),
            Metric("idle_in_txn_max_seconds", row["idle_txn"]),
        ]
        blk = self.query("""
            SELECT count(*) AS n, COALESCE(max(EXTRACT(EPOCH FROM now() - query_start)), 0) AS w
            FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0""")[0]
        m += [Metric("blocked_sessions", blk["n"]), Metric("blocking_max_wait_seconds", blk["w"])]

        lag = self.safe("""
            SELECT CASE WHEN pg_is_in_recovery()
                   THEN COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()), 0)
                   ELSE (SELECT COALESCE(max(EXTRACT(EPOCH FROM replay_lag)), 0) FROM pg_stat_replication)
                   END AS lag""")
        if lag:
            m.append(Metric("replication_lag_seconds", self.scalar(lag, 0)))

        dl = self.delta("deadlocks", self.scalar(self.query("SELECT sum(deadlocks) FROM pg_stat_database"), 0))
        if dl is not None:
            m.append(Metric("deadlocks_delta", dl))
        return m

    def collect_slow(self) -> list[Metric]:
        rows = self.safe("""
            SELECT COALESCE(max(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0)), 0) AS pct
            FROM pg_stat_user_tables WHERE n_live_tup + n_dead_tup > 10000""")
        return [Metric("max_dead_tuple_pct", self.scalar(rows, 0))] if rows else []

    def get_active_sessions(self) -> list[dict]:
        return self.query(ACTIVE_SESSIONS)

    def get_blocking_chain(self) -> list[dict]:
        return self.query(BLOCKING)

    def get_top_queries(self, limit: int = 20) -> list[dict]:
        return self.query(TOP_QUERIES, (int(limit),))

    def get_query_plan(self, query_ref: str):
        """query_ref is a query_id from pg_stat_statements or a SELECT statement.
        Uses EXPLAIN without ANALYZE, so the statement is planned but never executed."""
        sql = query_ref
        if query_ref.strip().lstrip("-").isdigit():
            rows = self.query("SELECT query FROM pg_stat_statements WHERE queryid = %s LIMIT 1",
                              (int(query_ref),))
            if not rows:
                return {"error": f"query_id {query_ref} not found in pg_stat_statements"}
            sql = rows[0]["query"]
        from ..agent.sql_guard import assert_select_only
        assert_select_only(sql, "postgres")
        version = int(self.scalar(self.query("SELECT current_setting('server_version_num')::int"), 0))
        generic = ", GENERIC_PLAN" if version >= 160000 and "$1" in sql else ""
        return self.query(f"EXPLAIN (FORMAT JSON{generic}) {sql}")

    def get_wait_stats(self) -> list[dict]:
        return self.query(WAITS)

    def get_session(self, session_id: str) -> list[dict]:
        return self.query("""SELECT pid, usename, datname, state, application_name,
                             EXTRACT(EPOCH FROM now() - xact_start) AS xact_seconds, left(query, 1000) AS query
                             FROM pg_stat_activity WHERE pid = %s""", (int(session_id),))

    def extra_tools(self):
        return {
            "table_health": lambda: self.query("""
                SELECT schemaname, relname, n_live_tup, n_dead_tup,
                       round(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 1) AS dead_pct,
                       seq_scan, idx_scan, last_autovacuum, last_autoanalyze
                FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 25"""),
            "locks": lambda: self.query("""
                SELECT l.pid, l.locktype, l.mode, l.granted, l.relation::regclass::text AS relation,
                       a.state, left(a.query, 500) AS query
                FROM pg_locks l JOIN pg_stat_activity a USING (pid)
                WHERE a.pid <> pg_backend_pid() ORDER BY l.granted, l.pid LIMIT 200"""),
        }
