from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from monitor.adapters.base import EngineAdapter, Metric
from monitor.config import Settings, Target
from monitor.store import init_db

ROOT = Path(__file__).resolve().parents[1]


class FakeAdapter(EngineAdapter):
    """Scripted adapter: responses are matched by substring of the SQL; every SQL statement is recorded."""

    def __init__(self, target: Target, responses: dict[str, object] | None = None, metrics=None):
        super().__init__(target, {})
        self.engine = target.engine
        self.responses = responses or {}
        self.metrics = metrics or []
        self.queries: list[str] = []
        self.privileged_sql: list[str] = []
        self.fail_on: set[str] = set()

    def _connect(self, role):  # pragma: no cover - never used
        raise AssertionError("fake adapter does not connect")

    def _answer(self, sql: str):
        for key, val in self.responses.items():
            if key in sql:
                return val(sql) if callable(val) else val
        return []

    def query(self, sql, params=None, max_rows=None):
        self.queries.append(sql)
        return self._answer(sql)

    @contextmanager
    def privileged(self):
        def run(sql, params=None, max_rows=10000):
            self.privileged_sql.append(sql)
            for f in self.fail_on:
                if f in sql:
                    raise RuntimeError(f"simulated failure for {f}")
            return self._answer(sql)
        yield run

    def collect_fast(self):
        return [Metric(**m) if isinstance(m, dict) else m for m in self.metrics]

    def get_active_sessions(self):
        return self._answer("ACTIVE")

    def get_blocking_chain(self):
        return self._answer("BLOCKING")

    def get_top_queries(self, limit=20):
        return self._answer("TOPQ")

    def get_query_plan(self, query_ref):
        return self._answer("PLAN")

    def get_wait_stats(self):
        return self._answer("WAITS")

    def get_session(self, session_id):
        return self._answer("SESSION")


def make_settings(tmp_path: Path, targets: list[Target] | None = None, rules=None, governance=None,
                  llm=None) -> Settings:
    raw = {
        "state_db_url": f"sqlite:///{tmp_path / 'state.db'}",
        "runbooks_dir": str(ROOT / "runbooks"),
        "incidents": {"cooldown_minutes": 30, "auto_resolve_minutes": 15},
        "llm": llm or {"enabled": True, "max_tool_calls": 5, "max_turns": 8, "server_side_fallback": False},
        "tool_limits": {"max_rows": 200, "max_result_chars": 20000},
        "notifications": {"routes": {}},
    }
    s = Settings(raw=raw, base_dir=ROOT, targets=targets or [], rules=rules or [], governance=governance or {})
    s.raw["runbooks_dir"] = "runbooks"
    return s


@pytest.fixture
def db(tmp_path):
    init_db(f"sqlite:///{tmp_path / 'state.db'}")
    return tmp_path


def pg_target(name="pg1"):
    return Target(name=name, engine="postgres", monitor={"user": "monitor"}, executor={"user": "postgres"})


def sf_target(name="sf1"):
    return Target(name=name, engine="snowflake", monitor={"user": "MONITOR_SVC"}, executor={"user": "GOV_SVC"},
                  limits={"max_warehouse_size": "LARGE"})
