"""Shared adapter interface. Every engine implements the same read-only diagnostics surface."""
from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from ..config import Target
from ..store.db import jsonable

log = logging.getLogger(__name__)


@dataclass
class Metric:
    name: str
    value: float
    labels: dict = field(default_factory=dict)

    @property
    def labels_key(self) -> str:
        return ",".join(f"{k}={v}" for k, v in sorted(self.labels.items()))


class EngineAdapter(ABC):
    engine: str = ""
    placeholder: str = "%s"   # DB-API parameter marker for this driver

    def __init__(self, target: Target, tool_limits: dict | None = None):
        self.target = target
        limits = tool_limits or {}
        self.max_rows = int(limits.get("max_rows", 200))
        self.timeout_s = int(limits.get("statement_timeout_seconds", 30))
        self._conn = None
        self._lock = threading.RLock()
        self._last_counters: dict[str, float] = {}

    # ---- connection handling -------------------------------------------------
    @abstractmethod
    def _connect(self, role: str):
        """Return a DB-API connection. role is 'monitor' (read-only) or 'executor'."""

    def _monitor_conn(self):
        if self._conn is None:
            self._conn = self._connect("monitor")
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self._conn = None

    @staticmethod
    def _rows(cur, max_rows: int) -> list[dict]:
        if cur.description is None:
            return []
        cols = [d[0] for d in cur.description]
        return [jsonable(dict(zip(cols, r))) for r in cur.fetchmany(max_rows)]

    def query(self, sql: str, params: tuple | list | None = None, max_rows: int | None = None) -> list[dict]:
        """Run a read-only statement on the monitor connection. Reconnects once on failure."""
        limit = max_rows or self.max_rows
        with self._lock:
            for attempt in (1, 2):
                conn = self._monitor_conn()   # a failed connect raises straight away (no pointless retry)
                try:
                    cur = conn.cursor()
                    try:
                        cur.execute(sql, params) if params is not None else cur.execute(sql)
                        return self._rows(cur, limit)
                    finally:
                        cur.close()
                except Exception:
                    if attempt == 2 or not self._is_connection_error():
                        raise
                    log.warning("%s: connection lost, reconnecting", self.target.name)
                    self.close()
        return []

    def _is_connection_error(self) -> bool:
        """After an error, decide whether the connection itself is broken."""
        try:
            cur = self._monitor_conn().cursor()
            cur.execute("SELECT 1")
            cur.fetchall()
            cur.close()
            return False
        except Exception:  # noqa: BLE001
            return True

    @contextmanager
    def privileged(self) -> Iterator[Callable[..., list[dict]]]:
        """Executor-credential session for approved changes. Yields run(sql, params=None) -> rows."""
        if not self.target.executor.get("user"):
            raise RuntimeError(f"{self.target.name} has no executor login configured; approved actions can't run")
        conn = self._connect("executor")

        def run(sql: str, params: tuple | list | None = None, max_rows: int = 10000) -> list[dict]:
            cur = conn.cursor()
            try:
                cur.execute(sql, params) if params is not None else cur.execute(sql)
                rows = self._rows(cur, max_rows)
                try:
                    conn.commit()
                except Exception:  # noqa: BLE001 - autocommit connections
                    pass
                return rows
            finally:
                cur.close()

        try:
            yield run
        finally:
            conn.close()

    def execute_privileged(self, sql: str, params: tuple | list | None = None) -> list[dict]:
        """Run one approved action with the executor credentials. Only the executor module calls this."""
        with self.privileged() as run:
            return run(sql, params, max_rows=self.max_rows)

    def safe(self, sql: str, params=None, default: Any = None, max_rows: int | None = None):
        """Query that tolerates missing views/permissions (returns default and logs)."""
        try:
            return self.query(sql, params, max_rows=max_rows)
        except Exception as e:  # noqa: BLE001
            log.debug("%s: optional query failed: %s", self.target.name, e)
            return default if default is not None else []

    def delta(self, key: str, value: float | None) -> float | None:
        """Turn a cumulative counter into a per-interval delta (None on first sample or reset)."""
        if value is None:
            return None
        prev = self._last_counters.get(key)
        self._last_counters[key] = value
        if prev is None or value < prev:
            return None
        return value - prev

    @staticmethod
    def scalar(rows: list[dict], default: float | None = None) -> float | None:
        if not rows:
            return default
        v = next(iter(rows[0].values()))
        return default if v is None else float(v)

    # ---- diagnostics surface -------------------------------------------------
    @abstractmethod
    def collect_fast(self) -> list[Metric]:
        """Cheap metrics polled every minute (sessions, blocking, long-running)."""

    def collect_slow(self) -> list[Metric]:
        """Heavier metrics polled every ~10 minutes (cost, job history, bloat)."""
        return []

    @abstractmethod
    def get_active_sessions(self) -> list[dict]: ...

    @abstractmethod
    def get_blocking_chain(self) -> list[dict]: ...

    @abstractmethod
    def get_top_queries(self, limit: int = 20) -> list[dict]: ...

    @abstractmethod
    def get_query_plan(self, query_ref: str) -> Any: ...

    @abstractmethod
    def get_wait_stats(self) -> list[dict]: ...

    def get_session(self, session_id: str) -> list[dict]:
        """Details of one session/query, used for action previews."""
        return []

    def health(self) -> dict:
        try:
            self.query("SELECT 1")
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:500]}

    def extra_tools(self) -> dict[str, Any]:
        """Engine-specific read-only diagnostics exposed to the agent: name -> callable(**kwargs)."""
        return {}
