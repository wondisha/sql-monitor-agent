"""Group events into incidents: dedup, flap suppression, auto-resolve."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store import Incident, IncidentEvent
from ..store.db import jsonable
from ..store.models import utcnow
from .rules import SEVERITIES, Event

OPEN_STATES = ("open", "investigating")


@dataclass
class IncidentUpdate:
    incident: Incident
    is_new: bool          # brand-new or reopened -> notify + investigate
    escalated: bool = False


class Correlator:
    def __init__(self, cooldown_minutes: int = 30, auto_resolve_minutes: int = 15):
        self.cooldown = timedelta(minutes=cooldown_minutes)
        self.auto_resolve = timedelta(minutes=auto_resolve_minutes)

    def process(self, s: Session, events: list[Event]) -> list[IncidentUpdate]:
        now = utcnow()
        updates: list[IncidentUpdate] = []
        for ev in events:
            inc = s.scalars(
                select(Incident).where(Incident.dedup_key == ev.dedup_key)
                .order_by(Incident.id.desc()).limit(1)
            ).first()
            context = jsonable({"metric": ev.metric.name, "labels": ev.metric.labels, **ev.detail})

            if inc and inc.status in OPEN_STATES:
                inc.last_seen_at = now
                inc.event_count += 1
                inc.context = {**(inc.context or {}), "latest": context}
                escalated = SEVERITIES.index(ev.rule.severity) < SEVERITIES.index(inc.severity)
                if escalated:
                    inc.severity = ev.rule.severity
                    s.add(IncidentEvent(incident_id=inc.id, kind="escalated", detail={"severity": inc.severity}))
                updates.append(IncidentUpdate(inc, is_new=False, escalated=escalated))
                continue

            if inc and inc.status == "resolved" and inc.resolved_at and now - inc.resolved_at < self.cooldown:
                # Flapping: reopen the same incident instead of creating a new one.
                inc.status, inc.resolved_at, inc.last_seen_at = "open", None, now
                inc.event_count += 1
                inc.context = {**(inc.context or {}), "latest": context}
                s.add(IncidentEvent(incident_id=inc.id, kind="reopened", detail=context))
                updates.append(IncidentUpdate(inc, is_new=False))
                continue

            inc = Incident(
                dedup_key=ev.dedup_key, target=ev.target, engine=ev.engine, rule_id=ev.rule.id,
                title=ev.rule.title, severity=ev.rule.severity, status="open",
                opened_at=now, last_seen_at=now, context={"first": context, "latest": context},
            )
            s.add(inc)
            s.flush()
            s.add(IncidentEvent(incident_id=inc.id, kind="fired", detail=context))
            updates.append(IncidentUpdate(inc, is_new=True))
        return updates

    def resolve_recovered(self, s: Session, cleared_keys: set[str]) -> list[Incident]:
        """Resolve open incidents whose check just ran and came back healthy."""
        if not cleared_keys:
            return []
        resolved = []
        for inc in s.scalars(select(Incident).where(Incident.status.in_(OPEN_STATES),
                                                    Incident.dedup_key.in_(cleared_keys))):
            inc.status, inc.resolved_at = "resolved", utcnow()
            s.add(IncidentEvent(incident_id=inc.id, kind="resolved", detail={"reason": "check passed again"}))
            resolved.append(inc)
        return resolved

    def resolve_stale(self, s: Session, healthy_targets: set[str]) -> list[Incident]:
        """Resolve incidents that stopped firing - only for targets we can currently observe."""
        cutoff = utcnow() - self.auto_resolve
        resolved = []
        for inc in s.scalars(select(Incident).where(Incident.status.in_(OPEN_STATES))):
            if inc.target in healthy_targets and inc.last_seen_at < cutoff:
                inc.status, inc.resolved_at = "resolved", utcnow()
                s.add(IncidentEvent(incident_id=inc.id, kind="resolved", detail={"reason": "condition cleared"}))
                resolved.append(inc)
        return resolved
