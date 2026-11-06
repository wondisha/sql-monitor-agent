from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import AuditLog, Base

_engine: Engine | None = None
_Session: sessionmaker | None = None


def init_db(url: str) -> Engine:
    global _engine, _Session
    kwargs = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("init_db() has not been called")
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    if _Session is None:
        raise RuntimeError("init_db() has not been called")
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def audit(session: Session, actor: str, event: str, target: str = "", **detail) -> None:
    session.add(AuditLog(actor=actor, event=event, target=target, detail=_jsonable(detail)))


def _jsonable(obj):
    """Make values JSON-safe for the JSON columns (datetimes, decimals, bytes)."""
    import datetime as _dt
    import decimal

    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (_dt.datetime, _dt.date, _dt.time)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return "0x" + bytes(obj).hex()
    if isinstance(obj, _dt.timedelta):
        return obj.total_seconds()
    return obj


jsonable = _jsonable
