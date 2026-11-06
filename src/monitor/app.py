"""Wires all components together. One App instance per process."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import select

from .actions import Executor
from .adapters import AdapterRegistry
from .config import Settings, load_settings
from .detector import Correlator, RuleEngine
from .detector.baseline import BaselineStore
from .detector.rules import SEVERITIES, Event, Rule
from .adapters.base import Metric
from .governance import SnowflakeUserGovernance
from .notify import Notifier
from .store import ActionRecord, Incident, MetricSample, init_db, session_scope
from .store.db import audit

log = logging.getLogger(__name__)

COLLECTOR_ERROR_RULE = Rule(id="collector_error", metric="collector_error", severity="P2",
                            title="Monitoring cannot reach target")


class App:
    def __init__(self, settings: Settings | None = None, settings_path: str | Path = "config/settings.yaml",
                 llm_client=None):
        self.settings = settings or load_settings(settings_path)
        init_db(self.settings.state_db_url)
        self.registry = AdapterRegistry(self.settings.targets, self.settings.section("tool_limits"))
        self.baseline = BaselineStore()
        self.rules = RuleEngine.from_config(self.settings.rules, self.baseline)
        inc_cfg = self.settings.section("incidents")
        self.correlator = Correlator(int(inc_cfg.get("cooldown_minutes", 30)), int(inc_cfg.get("auto_resolve_minutes", 15)))
        self.notifier = Notifier(self.settings)
        self.executor = Executor(self.settings, self.registry)
        self.governance = SnowflakeUserGovernance(self.settings, self.registry,
                                                  notify=lambda t, b: self.notifier.message(t, b))
        self._llm_client = llm_client
        self._investigator = None
        self._pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="investigate")
        self.healthy: set[str] = set()
        self.scheduler = None   # set by collector.build_scheduler when collectors run in this process

    # ---- targets added/removed at runtime from the dashboard ------------------------------
    def add_target(self, target) -> None:
        from .adapters import build_adapter
        self.settings.targets.append(target)
        self.registry.register(build_adapter(target, self.settings.section("tool_limits")))
        if self.scheduler is not None:
            from .collector.scheduler import schedule_target
            schedule_target(self, target.name)
            self.scheduler.add_job(self.collect, args=[target.name, False, True], id=f"first:{target.name}",
                                   replace_existing=True)   # collect right away instead of waiting a cycle

    def remove_target(self, name: str) -> None:
        if self.scheduler is not None:
            from .collector.scheduler import unschedule_target
            unschedule_target(self, name)
        self.registry.remove(name)
        self.settings.targets[:] = [t for t in self.settings.targets if t.name != name]
        self.healthy.discard(name)

    @property
    def investigator(self):
        if self._investigator is None:
            from .agent.investigator import Investigator
            from .agent.tools import ToolBox
            self._investigator = Investigator(self.settings, ToolBox(self.settings, self.registry, self.baseline),
                                              self.executor, client=self._llm_client, on_rca=self._after_rca)
        return self._investigator

    # ---- pipeline ----------------------------------------------------------------------
    def collect(self, target: str, slow: bool = False, both: bool = False) -> list[Event]:
        """Fast cycle collects cheap metrics; slow cycle only the heavy ones (so rule streaks aren't double-counted)."""
        adapter = self.registry.get(target)
        try:
            if both:
                metrics = adapter.collect_fast() + adapter.collect_slow()
            else:
                metrics = adapter.collect_slow() if slow else adapter.collect_fast()
            self.healthy.add(target)
        except Exception as e:  # noqa: BLE001
            log.warning("collection failed for %s: %s", target, e)
            self.healthy.discard(target)
            adapter.close()
            ev = Event(target, adapter.engine, COLLECTOR_ERROR_RULE, Metric("collector_error", 1),
                       {"error": str(e)[:500]})
            self._handle_events([ev])
            return [ev]

        from .store.models import utcnow
        ts = utcnow()   # one timestamp per collection cycle, so "latest readings" groups them together
        with session_scope() as s:
            s.add_all(MetricSample(ts=ts, target=target, name=m.name, labels_key=m.labels_key, value=float(m.value))
                      for m in metrics)
        cleared: set[str] = {f"{target}|{COLLECTOR_ERROR_RULE.id}|"}   # collection worked -> reachable again
        events = self.rules.evaluate(target, adapter.engine, metrics, cleared)
        self._handle_events(events, cleared)
        return events

    def _handle_events(self, events: list[Event], cleared: set[str] | None = None) -> None:
        new_ids = []
        with session_scope() as s:
            for inc in self.correlator.resolve_recovered(s, cleared or set()):
                self.notifier.incident_resolved(inc)
            for upd in self.correlator.process(s, events):
                if upd.is_new or upd.escalated:
                    self.notifier.incident_opened(upd.incident)
                    upd.incident.last_notified_at = upd.incident.last_seen_at
                if upd.is_new:
                    new_ids.append((upd.incident.id, upd.incident.severity, upd.incident.rule_id))
            for inc in self.correlator.resolve_stale(s, self.healthy):
                self.notifier.incident_resolved(inc)
        for inc_id, sev, rule_id in new_ids:
            if self._should_investigate(sev, rule_id):
                self.submit_investigation(inc_id)
            else:
                with session_scope() as s:
                    s.get(Incident, inc_id).rca_status = "skipped"

    def _should_investigate(self, severity: str, rule_id: str) -> bool:
        llm = self.settings.section("llm")
        if not llm.get("enabled", True) or rule_id == "collector_error":
            return False
        threshold = llm.get("investigate_min_severity", "P3")
        return SEVERITIES.index(severity) <= SEVERITIES.index(threshold)

    def submit_investigation(self, incident_id: int):
        return self._pool.submit(self.investigator.investigate, incident_id)

    def _after_rca(self, incident_id: int) -> None:
        with session_scope() as s:
            inc = s.get(Incident, incident_id)
            n = len(s.scalars(select(ActionRecord.id).where(ActionRecord.incident_id == incident_id,
                                                            ActionRecord.status == "proposed")).all())
            self.notifier.incident_rca(inc, n)

    def run_governance(self, actor: str = "scheduler") -> list[dict]:
        cfg = (self.settings.governance or {}).get("snowflake_inactive_users", {}) or {}
        if not cfg.get("enabled"):
            return []
        out = []
        for target in cfg.get("targets", []):
            if target not in self.registry.names():
                log.warning("governance target %s is not an enabled target", target)
                continue
            try:
                out.append(self.governance.run(target, actor=actor))
            except Exception as e:  # noqa: BLE001
                log.exception("governance run failed for %s", target)
                with session_scope() as s:
                    audit(s, actor, "governance_run_failed", target, error=str(e)[:500])
                out.append({"target": target, "error": str(e)[:500]})
        return out

    def prune_metrics(self, keep_days: int = 14) -> int:
        from datetime import timedelta
        from sqlalchemy import delete
        from .store.models import utcnow
        with session_scope() as s:
            res = s.execute(delete(MetricSample).where(MetricSample.ts < utcnow() - timedelta(days=keep_days)))
            return res.rowcount or 0

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        for _, a in self.registry.items():
            a.close()
