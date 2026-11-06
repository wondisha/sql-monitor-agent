"""Snowflake adapter.

Real-time signals come from INFORMATION_SCHEMA table functions (no lag, need a current database).
Trend/cost signals come from SNOWFLAKE.ACCOUNT_USAGE (up to ~45 min - 3 h lag).
All column names are lower-cased so callers see the same shape as SHOW command output.
"""
from __future__ import annotations

import logging
import re
import time

from .base import EngineAdapter, Metric

log = logging.getLogger(__name__)
_QID = re.compile(r"^[0-9a-fA-F-]{36}$")
SYSTEM_WH_PREFIX = "SYSTEM$"          # Snowflake-managed warehouses (e.g. notebooks) are not audited
_MANAGED_WH = re.compile(r"^(SYSTEM\$|COMPUTE_SERVICE_WH_|CLOUD_SERVICES_ONLY$)", re.IGNORECASE)
NEVER_SUSPENDS = 10 ** 6              # auto_suspend NULL/0 means the warehouse never suspends


def _managed(name) -> bool:
    """Snowflake-internal pools (serverless tasks, cloud services, notebooks): not user-tunable warehouses."""
    return bool(_MANAGED_WH.match(str(name or "")))


def _num(v, default: float = 0) -> float:
    try:
        return default if v in (None, "", "null") else float(v)
    except (TypeError, ValueError):
        return default


def _q(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'

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
    # Cost model (measured on a real account): every query that reads INFORMATION_SCHEMA table functions or
    # ACCOUNT_USAGE resumes the warehouse, so polling those every minute kept an XS warehouse running 24/7
    # (~24 credits/day). SHOW commands run in cloud services and use no warehouse. So:
    #   fast  (every minute)   : SHOW WAREHOUSES / SHOW LOCKS only            -> free
    #   slow  (every ~10 min)  : config audit via SHOW                         -> free
    #   heavy (every 30 min)   : one short warehouse burst (query history, credits, spill, tasks, logins)
    #   daily (every 6 h)      : cache, pruning, idle credits, cloud services  (same burst when due)
    # Between bursts the cached heavy/daily values are re-emitted so incidents don't flap or auto-resolve.

    def _intervals(self) -> tuple[int, int]:
        lim = self.target.limits or {}
        return int(lim.get("heavy_interval_minutes", 30)) * 60, int(lim.get("daily_interval_hours", 6)) * 3600

    def _cached(self, key: str, interval_s: int, fn) -> list[Metric]:
        cache = self.__dict__.setdefault("_metric_cache", {})
        now = time.monotonic()
        hit = cache.get(key)
        if hit and now - hit[0] < interval_s:
            return hit[1]
        try:
            metrics = fn()
        except Exception as e:  # noqa: BLE001 - keep serving the previous values; the error is logged
            log.warning("%s: %s checks failed: %s", self.target.name, key, str(e)[:300])
            return hit[1] if hit else []
        cache[key] = (now, metrics)
        return metrics

    def _show_warehouses(self) -> list[dict]:
        return [w for w in self.query("SHOW WAREHOUSES", max_rows=10000)
                if not str(w.get("name", "")).upper().startswith(SYSTEM_WH_PREFIX)]

    def collect_fast(self) -> list[Metric]:
        m: list[Metric] = []
        running = queued = 0
        for w in self._show_warehouses():
            lab = {"warehouse": w["name"]}
            r, q = _num(w.get("running")), _num(w.get("queued"))
            running, queued = running + r, queued + q
            m += [Metric("wh_running_queries", r, lab), Metric("wh_queued_queries", q, lab)]
        m += [Metric("active_sessions", running), Metric("queued_queries", queued)]
        try:   # needs MONITOR ON ACCOUNT; without it, blocked queries come from the 30-minute pass
            locks = self.query("SHOW LOCKS IN ACCOUNT", max_rows=10000)
            m.append(Metric("blocked_sessions", sum(1 for x in locks if str(x.get("status", "")).upper() == "WAITING")))
        except Exception:  # noqa: BLE001
            pass
        return m

    def collect_slow(self) -> list[Metric]:
        heavy_s, daily_s = self._intervals()
        return (self._config_audit()
                + self._cached("heavy", heavy_s, self._heavy_metrics)
                + self._cached("daily", daily_s, self._daily_metrics))

    def _config_audit(self) -> list[Metric]:
        """Warehouse and resource-monitor settings. SHOW commands only: no warehouse credits."""
        m: list[Metric] = []
        acct = self.safe("SHOW PARAMETERS LIKE 'STATEMENT_TIMEOUT_IN_SECONDS' IN ACCOUNT")
        acct_timeout = _num(acct[0].get("value"), 172800) if acct else 172800
        for w in self._show_warehouses():
            name, lab = w["name"], {"warehouse": w["name"]}
            suspend = _num(w.get("auto_suspend"), 0)
            m.append(Metric("wh_auto_suspend_seconds", suspend if suspend > 0 else NEVER_SUSPENDS, lab))
            m.append(Metric("wh_auto_resume_off", 0 if str(w.get("auto_resume")).lower() == "true" else 1, lab))
            m.append(Metric("wh_no_resource_monitor",
                            1 if str(w.get("resource_monitor") or "null").lower() in ("null", "", "none") else 0, lab))
            p = self.safe(f"SHOW PARAMETERS LIKE 'STATEMENT_TIMEOUT_IN_SECONDS' IN WAREHOUSE {_q(name)}")
            m.append(Metric("wh_statement_timeout_seconds", _num(p[0].get("value"), acct_timeout) if p else acct_timeout,
                            lab))
            max_c, started = _num(w.get("max_cluster_count"), 1), _num(w.get("started_clusters"))
            m.append(Metric("wh_multicluster_at_max",
                            1 if max_c > 1 and started >= max_c and _num(w.get("queued")) > 0 else 0, lab))
        for r in self.safe("SHOW RESOURCE MONITORS"):
            lab = {"monitor": r["name"]}
            quota = _num(r.get("credit_quota"))
            m.append(Metric("rm_used_pct", 100.0 * _num(r.get("used_credits")) / quota if quota else 0, lab))
            no_suspend = all(str(r.get(k) or "null").lower() in ("null", "") for k in ("suspend_at", "suspend_immediately_at"))
            m.append(Metric("rm_no_suspend", 1 if no_suspend else 0, lab))
        return m

    def _heavy_metrics(self) -> list[Metric]:
        return [x for x in self._heavy_raw() if not _managed(x.labels.get("warehouse"))]

    def _heavy_raw(self) -> list[Metric]:
        """Every 30 min, one short warehouse burst."""
        m: list[Metric] = []
        q = self.query("""
            SELECT COALESCE(MAX(IFF(execution_status = 'RUNNING',
                       DATEDIFF('second', start_time, CURRENT_TIMESTAMP()), 0)), 0) AS longest,
                   COUNT_IF(execution_status LIKE 'FAILED%%') AS failed,
                   COUNT_IF(execution_status = 'BLOCKED') AS blocked
            FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY(
                END_TIME_RANGE_START => DATEADD('minute', -30, CURRENT_TIMESTAMP()), RESULT_LIMIT => 1000))""")[0]
        m += [Metric("longest_query_seconds", q["longest"]), Metric("failed_queries_30m", q["failed"]),
              Metric("blocked_queries", q["blocked"])]
        for r in self.safe("""
                SELECT warehouse_name, SUM(credits_used) AS credits
                FROM TABLE(INFORMATION_SCHEMA.WAREHOUSE_METERING_HISTORY(DATEADD('hour', -1, CURRENT_TIMESTAMP())))
                GROUP BY warehouse_name"""):
            m.append(Metric("warehouse_credits_1h", r["credits"] or 0, {"warehouse": r["warehouse_name"]}))
        # Spill columns exist only in ACCOUNT_USAGE (lags up to ~45 min), so this is a 1-hour window.
        for r in self.safe("""
                SELECT warehouse_name,
                       SUM(bytes_spilled_to_local_storage) / POWER(1024, 3) AS local_gb,
                       SUM(bytes_spilled_to_remote_storage) / POWER(1024, 3) AS remote_gb
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE end_time > DATEADD('hour', -1, CURRENT_TIMESTAMP()) AND warehouse_name IS NOT NULL
                GROUP BY warehouse_name"""):
            lab = {"warehouse": r["warehouse_name"]}
            m += [Metric("wh_local_spill_gb_1h", r["local_gb"] or 0, lab),
                  Metric("wh_remote_spill_gb_1h", r["remote_gb"] or 0, lab)]
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

    def _daily_metrics(self) -> list[Metric]:
        return [x for x in self._daily_raw() if not _managed(x.labels.get("warehouse"))]

    def _daily_raw(self) -> list[Metric]:
        """Every 6 h: efficiency over the last day (ACCOUNT_USAGE)."""
        m: list[Metric] = []
        min_gb = float((self.target.limits or {}).get("cache_check_min_scanned_gb", 10))
        for r in self.safe("""
                SELECT warehouse_name, SUM(bytes_scanned) / POWER(1024, 3) AS scanned_gb,
                       100 * SUM(bytes_scanned * percentage_scanned_from_cache) / NULLIF(SUM(bytes_scanned), 0) AS cache_pct,
                       COUNT_IF(partitions_total >= 1000 AND partitions_scanned >= 0.8 * partitions_total) AS poor_pruning
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE end_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
                  AND warehouse_name IS NOT NULL AND bytes_scanned > 0
                GROUP BY warehouse_name"""):
            lab = {"warehouse": r["warehouse_name"]}
            if _num(r.get("scanned_gb")) >= min_gb:      # cache % is meaningless on tiny volumes
                m.append(Metric("wh_cache_hit_pct_24h", _num(r.get("cache_pct")), lab))
            m.append(Metric("wh_poor_pruning_queries_24h", _num(r.get("poor_pruning")), lab))
        # Idle = compute billed but not attributed to any query. Attribution lags up to ~8 h, so use 8-32 h ago.
        for r in self.safe("""
                SELECT warehouse_name, SUM(credits_used_compute) AS compute,
                       SUM(credits_attributed_compute_queries) AS attributed
                FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
                WHERE start_time BETWEEN DATEADD('hour', -32, CURRENT_TIMESTAMP()) AND DATEADD('hour', -8, CURRENT_TIMESTAMP())
                GROUP BY warehouse_name"""):
            compute = _num(r.get("compute"))
            if compute >= 1:                               # ignore warehouses that barely ran
                idle = max(compute - _num(r.get("attributed")), 0)
                m.append(Metric("wh_idle_credit_pct_24h", 100.0 * idle / compute, {"warehouse": r["warehouse_name"]}))
        cs = self.safe("""
            SELECT SUM(credits_used_compute) AS compute, SUM(credits_used_cloud_services) AS cloud
            FROM SNOWFLAKE.ACCOUNT_USAGE.METERING_DAILY_HISTORY
            WHERE usage_date = DATEADD('day', -1, CURRENT_DATE())""")
        if cs and _num(cs[0].get("compute")) >= 1:
            m.append(Metric("cloud_services_pct_1d", 100.0 * _num(cs[0].get("cloud")) / _num(cs[0].get("compute"))))
        return m

    def warehouse_state(self, name: str) -> list[dict]:
        """Current settings of one warehouse (used for action previews / rollback values)."""
        rows = [w for w in self.query("SHOW WAREHOUSES", max_rows=10000) if w.get("name") == name]
        keep = ("name", "state", "size", "auto_suspend", "auto_resume", "min_cluster_count", "max_cluster_count",
                "scaling_policy", "resource_monitor", "running", "queued")
        out = [{k: w.get(k) for k in keep} for w in rows]
        if out:
            p = self.safe(f"SHOW PARAMETERS LIKE 'STATEMENT_TIMEOUT_IN_SECONDS' IN WAREHOUSE {_q(name)}")
            out[0]["statement_timeout_in_seconds"] = p[0].get("value") if p else "unknown (needs MONITOR on warehouse)"
        return out

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
            "warehouse_config": lambda: {
                "warehouses": [self.warehouse_state(w["name"])[0] for w in self._show_warehouses()],
                "resource_monitors": self.safe("SHOW RESOURCE MONITORS"),
                "account_statement_timeout": self.safe("SHOW PARAMETERS LIKE 'STATEMENT_TIMEOUT%' IN ACCOUNT"),
            },
            "spilling_queries": lambda: self.query("""
                SELECT query_id, warehouse_name, warehouse_size, user_name, end_time,
                       ROUND(total_elapsed_time / 1000, 1) AS elapsed_seconds,
                       ROUND(bytes_spilled_to_local_storage / POWER(1024, 3), 2) AS local_spill_gb,
                       ROUND(bytes_spilled_to_remote_storage / POWER(1024, 3), 2) AS remote_spill_gb,
                       ROUND(bytes_scanned / POWER(1024, 3), 2) AS scanned_gb, partitions_scanned, partitions_total,
                       LEFT(query_text, 1500) AS query_text
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE end_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
                  AND (bytes_spilled_to_local_storage > 0 OR bytes_spilled_to_remote_storage > 0)
                ORDER BY bytes_spilled_to_remote_storage DESC, bytes_spilled_to_local_storage DESC LIMIT 20"""),
            "cache_and_pruning": lambda: self.query("""
                SELECT warehouse_name, COUNT(*) AS queries, ROUND(SUM(bytes_scanned) / POWER(1024, 3), 2) AS scanned_gb,
                       ROUND(100 * SUM(bytes_scanned * percentage_scanned_from_cache)
                             / NULLIF(SUM(bytes_scanned), 0), 1) AS cache_hit_pct,
                       COUNT_IF(partitions_total >= 1000 AND partitions_scanned >= 0.8 * partitions_total)
                           AS poor_pruning_queries,
                       ROUND(100 * AVG(partitions_scanned / NULLIF(partitions_total, 0)), 1) AS avg_pct_partitions_scanned
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE end_time > DATEADD('hour', -24, CURRENT_TIMESTAMP()) AND warehouse_name IS NOT NULL
                GROUP BY 1 ORDER BY scanned_gb DESC"""),
            "worst_pruning_queries": lambda: self.query("""
                SELECT query_id, warehouse_name, partitions_scanned, partitions_total,
                       ROUND(bytes_scanned / POWER(1024, 3), 2) AS scanned_gb, LEFT(query_text, 1500) AS query_text
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE end_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
                  AND partitions_total >= 1000 AND partitions_scanned >= 0.8 * partitions_total
                ORDER BY bytes_scanned DESC LIMIT 20"""),
            "idle_and_cost": lambda: {
                "per_warehouse_7d": self.query("""
                    SELECT warehouse_name, ROUND(SUM(credits_used_compute), 3) AS compute_credits,
                           ROUND(SUM(credits_attributed_compute_queries), 3) AS query_credits,
                           ROUND(100 * (1 - SUM(credits_attributed_compute_queries)
                                 / NULLIF(SUM(credits_used_compute), 0)), 1) AS idle_pct
                    FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
                    WHERE start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                    GROUP BY 1 ORDER BY compute_credits DESC"""),
                "cloud_services_daily": self.query("""
                    SELECT usage_date, ROUND(SUM(credits_used_compute), 3) AS compute,
                           ROUND(SUM(credits_used_cloud_services), 3) AS cloud_services,
                           ROUND(SUM(credits_adjustment_cloud_services), 3) AS free_adjustment
                    FROM SNOWFLAKE.ACCOUNT_USAGE.METERING_DAILY_HISTORY
                    WHERE usage_date > DATEADD('day', -7, CURRENT_DATE()) GROUP BY 1 ORDER BY 1"""),
            },
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
