"""State store schema: metrics, incidents, proposed actions, governance cases, audit log."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class MetricSample(Base):
    __tablename__ = "metric_samples"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    target: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(128))
    labels_key: Mapped[str] = mapped_column(String(512), default="")
    value: Mapped[float] = mapped_column(Float)

    __table_args__ = (Index("ix_metric_lookup", "target", "name", "labels_key", "ts"),)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(512), index=True)
    target: Mapped[str] = mapped_column(String(128))
    engine: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(4))
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | investigating | resolved
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    rca: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rca_status: Mapped[str] = mapped_column(String(32), default="pending")  # pending|running|done|failed|skipped
    rca_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    kind: Mapped[str] = mapped_column(String(64))  # fired | notified | rca | action | resolved | note
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class ActionRecord(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    target: Mapped[str] = mapped_column(String(128))
    action_type: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    rendered_sql: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[str] = mapped_column(String(16), default="medium")
    rationale: Mapped[str] = mapped_column(Text, default="")
    rollback: Mapped[str] = mapped_column(Text, default="")
    # proposed -> approved -> executed | failed ; proposed -> rejected ; script_only
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class GovernanceCase(Base):
    """One Snowflake user moving through the inactive-user lifecycle."""
    __tablename__ = "governance_cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(128))
    user_name: Mapped[str] = mapped_column(String(256), index=True)
    # flagged -> approved -> disabled -> dropped ; flagged -> kept ; disabled -> cancelled ; * -> failed
    state: Mapped[str] = mapped_column(String(32), default="flagged")
    reason: Mapped[str] = mapped_column(Text, default="")
    last_success_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    user_created_on: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    roles: Mapped[list] = mapped_column(JSON, default=list)
    snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    flagged_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dropped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    keep_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    orphaned_roles: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    """Append-only. The application never updates or deletes rows here."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(128), default="")
    event: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
