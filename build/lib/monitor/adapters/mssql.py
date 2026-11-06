from __future__ import annotations

import re

from .base import EngineAdapter, Metric

ACTIVE_SESSIONS = """
SELECT r.session_id, s.login_name, s.host_name, s.program_name, DB_NAME(r.database_id) AS db,
       r.status, r.command, r.wait_type, r.wait_time / 1000.0 AS wait_seconds,
       r.total_elapsed_time / 1000.0 AS elapsed_seconds, r.blocking_session_id,
       r.cpu_time, r.logical_reads, LEFT(t.text, 2000) AS query
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.is_user_process = 1 AND r.session_id <> @@SPID
ORDER BY r.total_elapsed_time DESC
"""

BLOCKING = """
SELECT r.session_id AS blocked_session, r.blocking_session_id AS blocker_session,
       r.wait_type, r.wait_resource, r.wait_time / 1000.0 AS wait_seconds,
       DB_NAME(r.database_id) AS db, s.login_name AS blocked_login, LEFT(t.text, 2000) AS blocked_query,
       bs.login_name AS blocker_login, bs.status AS blocker_status, bs.open_transaction_count AS blocker_open_trans,
       LEFT(bt.text, 2000) AS blocker_last_query
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
LEFT JOIN sys.dm_exec_sessions bs ON bs.session_id = r.blocking_session_id
LEFT JOIN sys.dm_exec_connections bc ON bc.session_id = r.blocking_session_id
OUTER APPLY sys.dm_exec_sql_text(bc.most_recent_sql_handle) bt
WHERE r.blocking_session_id <> 0
ORDER BY r.wait_time DESC
"""

TOP_QUERIES = """
SELECT TOP (?) CONVERT(varchar(20), qs.query_hash, 1) AS query_id, qs.execution_count AS calls,
       qs.total_elapsed_time / 1000.0 AS total_ms,
       qs.total_elapsed_time / 1000.0 / NULLIF(qs.execution_count, 0) AS mean_ms,
       qs.total_worker_time / 1000.0 AS cpu_ms, qs.total_logical_reads AS logical_reads,
       qs.total_spills AS spills, qs.last_execution_time,
       LEFT(SUBSTRING(t.text, qs.statement_start_offset / 2 + 1,
            (CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(t.text) ELSE qs.statement_end_offset END
             - qs.statement_start_offset) / 2 + 1), 2000) AS query
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
ORDER BY qs.total_elapsed_time DESC
"""

# Benign/background waits excluded from wait analysis.
_BENIGN = ("SLEEP_TASK", "BROKER_TASK_STOP", "BROKER_TO_FLUSH", "SQLTRACE_BUFFER_FLUSH", "CLR_AUTO_EVENT",
           "CLR_MANUAL_EVENT", "LAZYWRITER_SLEEP", "CHECKPOINT_QUEUE", "WAITFOR", "XE_TIMER_EVENT",
           "XE_DISPATCHER_WAIT", "FT_IFTS_SCHEDULER_IDLE_WAIT", "LOGMGR_QUEUE", "REQUEST_FOR_DEADLOCK_SEARCH",
           "DIRTY_PAGE_POLL", "HADR_FILESTREAM_IOMGR_IOCOMPLETION", "SP_SERVER_DIAGNOSTICS_SLEEP",
           "QDS_PERSIST_TASK_MAIN_LOOP_SLEEP", "QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP",
           "SQLTRACE_INCREMENTAL_FLUSH_SLEEP", "BROKER_EVENTHANDLER", "SOS_WORK_DISPATCHER")

WAITS = f"""
SELECT TOP 25 wait_type, waiting_tasks_count, wait_time_ms / 1000.0 AS wait_seconds,
       signal_wait_time_ms / 1000.0 AS signal_seconds
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN ({",".join(f"'{w}'" for w in _BENIGN)}) AND wait_type NOT LIKE 'PREEMPTIVE_%'
  AND waiting_tasks_count > 0
ORDER BY wait_time_ms DESC
"""

DEADLOCKS_XE = """
SELECT TOP 5 xed.value('@timestamp', 'datetime2') AS ts, CAST(xed.query('.') AS nvarchar(max)) AS graph
FROM (SELECT CAST(t.target_data AS XML) AS td
      FROM sys.dm_xe_session_targets t
      JOIN sys.dm_xe_sessions s ON s.address = t.event_session_address
      WHERE s.name = 'system_health' AND t.target_name = 'ring_buffer') x
CROSS APPLY x.td.nodes('RingBufferTarget/event[@name="xml_deadlock_report"]') AS q(xed)
ORDER BY ts DESC
"""

_HASH = re.compile(r"^0x[0-9A-Fa-f]{16}$")


class MSSQLAdapter(EngineAdapter):
    engine = "mssql"
    placeholder = "?"

    def _connect(self, role: str):
        import pyodbc

        cfg = self.target.monitor if role == "monitor" else self.target.executor
        parts = [
            f"DRIVER={{{cfg.get('driver', 'ODBC Driver 18 for SQL Server')}}}",
            f"SERVER={cfg.get('server')}",
            f"DATABASE={cfg.get('database', 'master')}",
            f"UID={cfg.get('user')}", f"PWD={cfg.get('password')}",
            "Encrypt=yes",
            f"TrustServerCertificate={'yes' if cfg.get('trust_server_certificate') else 'no'}",
            "APP=sql-monitor-agent",
        ]
        if role == "monitor":
            parts.append("ApplicationIntent=ReadOnly")
        conn = pyodbc.connect(";".join(parts), autocommit=True, timeout=10)
        conn.timeout = self.timeout_s
        return conn

    def collect_fast(self) -> list[Metric]:
        m: list[Metric] = []
        row = self.query("""
            SELECT (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) AS conns,
                   (SELECT COUNT(*) FROM sys.dm_exec_requests r JOIN sys.dm_exec_sessions s
                      ON s.session_id = r.session_id WHERE s.is_user_process = 1 AND r.session_id <> @@SPID) AS active,
                   (SELECT COALESCE(MAX(r.total_elapsed_time), 0) / 1000.0 FROM sys.dm_exec_requests r
                      JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
                      WHERE s.is_user_process = 1 AND r.session_id <> @@SPID) AS longest,
                   (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id <> 0) AS blocked,
                   (SELECT COALESCE(MAX(wait_time), 0) / 1000.0 FROM sys.dm_exec_requests
                      WHERE blocking_session_id <> 0) AS blocked_wait""")[0]
        m += [
            Metric("connections", row["conns"]),
            Metric("active_sessions", row["active"]),
            Metric("longest_query_seconds", row["longest"]),
            Metric("blocked_sessions", row["blocked"]),
            Metric("blocking_max_wait_seconds", row["blocked_wait"]),
        ]
        dl = self.safe("""SELECT cntr_value FROM sys.dm_os_performance_counters
                          WHERE counter_name = 'Number of Deadlocks/sec' AND instance_name = '_Total'""")
        d = self.delta("deadlocks", self.scalar(dl)) if dl else None
        if d is not None:
            m.append(Metric("deadlocks_delta", d))
        lag = self.safe("SELECT COALESCE(MAX(secondary_lag_seconds), 0) FROM sys.dm_hadr_database_replica_states")
        if lag:
            m.append(Metric("replication_lag_seconds", self.scalar(lag, 0)))
        return m

    def collect_slow(self) -> list[Metric]:
        m: list[Metric] = []
        jobs = self.safe("""
            SELECT COUNT(*) FROM msdb.dbo.sysjobhistory
            WHERE step_id = 0 AND run_status = 0
              AND msdb.dbo.agent_datetime(run_date, run_time) > DATEADD(minute, -15, GETDATE())""")
        if jobs:
            m.append(Metric("agent_job_failures_15m", self.scalar(jobs, 0)))
        # Free tempdb = unallocated space now + room the data files can still autogrow into
        # (disk free space for unlimited files, max_size - size for capped files).
        tmp = self.safe("""
            SELECT (SELECT SUM(unallocated_extent_page_count) * 8 / 1024.0 FROM tempdb.sys.dm_db_file_space_usage)
                 + COALESCE((SELECT MIN(vs.available_bytes) / 1048576.0
                             FROM tempdb.sys.database_files df
                             CROSS APPLY sys.dm_os_volume_stats(DB_ID('tempdb'), df.file_id) vs
                             WHERE df.type = 0 AND df.growth > 0 AND df.max_size = -1),
                            (SELECT SUM(CAST(df.max_size - df.size AS bigint)) * 8 / 1024.0
                             FROM tempdb.sys.database_files df
                             WHERE df.type = 0 AND df.growth > 0 AND df.max_size > 0), 0)""")
        if tmp:
            m.append(Metric("tempdb_free_mb", self.scalar(tmp, 0)))
        return m

    def get_active_sessions(self) -> list[dict]:
        return self.query(ACTIVE_SESSIONS)

    def get_blocking_chain(self) -> list[dict]:
        return self.query(BLOCKING)

    def get_top_queries(self, limit: int = 20) -> list[dict]:
        return self.query(TOP_QUERIES, (int(limit),))

    def get_query_plan(self, query_ref: str):
        """query_ref is a query_hash like 0x1A2B3C4D5E6F7081 (from get_top_queries). Returns cached showplan XML."""
        if not _HASH.match(query_ref.strip()):
            return {"error": "For SQL Server pass a query_hash such as 0x1A2B3C4D5E6F7081 from get_top_queries"}
        rows = self.query("""
            SELECT TOP 1 CAST(qp.query_plan AS nvarchar(max)) AS plan_xml
            FROM sys.dm_exec_query_stats qs CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
            WHERE qs.query_hash = CONVERT(binary(8), ?, 1)
            ORDER BY qs.total_elapsed_time DESC""", (query_ref.strip(),))
        if rows and rows[0].get("plan_xml"):
            rows[0]["plan_xml"] = rows[0]["plan_xml"][:15000]
        return rows

    def get_wait_stats(self) -> list[dict]:
        return self.query(WAITS)

    def get_session(self, session_id: str) -> list[dict]:
        return self.query("""SELECT s.session_id, s.login_name, s.host_name, s.program_name, s.status,
                             s.open_transaction_count FROM sys.dm_exec_sessions s WHERE s.session_id = ?""",
                          (int(session_id),))

    def extra_tools(self):
        return {
            "recent_deadlocks": lambda: self.safe(DEADLOCKS_XE),
            "missing_indexes": lambda: self.query("""
                SELECT TOP 20 DB_NAME(d.database_id) AS db, d.statement AS table_name, d.equality_columns,
                       d.inequality_columns, d.included_columns, s.user_seeks, s.avg_user_impact,
                       s.avg_total_user_cost
                FROM sys.dm_db_missing_index_details d
                JOIN sys.dm_db_missing_index_groups g ON g.index_handle = d.index_handle
                JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle
                ORDER BY s.avg_total_user_cost * s.avg_user_impact * s.user_seeks DESC"""),
            "failed_agent_jobs": lambda: self.safe("""
                SELECT TOP 20 j.name AS job, h.step_name, msdb.dbo.agent_datetime(h.run_date, h.run_time) AS run_at,
                       LEFT(h.message, 1000) AS message
                FROM msdb.dbo.sysjobhistory h JOIN msdb.dbo.sysjobs j ON j.job_id = h.job_id
                WHERE h.run_status = 0 ORDER BY run_at DESC"""),
        }
