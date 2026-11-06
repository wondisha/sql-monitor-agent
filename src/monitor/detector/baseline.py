"""Rolling 7-day baselines computed from stored metric samples, cached for a few minutes."""
from __future__ import annotations

import math
import time
from datetime import timedelta

from sqlalchemy import func, select

from ..store import MetricSample, session_scope
from ..store.models import utcnow


class BaselineStore:
    def __init__(self, window_days: int = 7, cache_seconds: int = 900):
        self.window = timedelta(days=window_days)
        self.cache_seconds = cache_seconds
        self._cache: dict[tuple, tuple[float, tuple | None]] = {}

    def __call__(self, target: str, metric: str, labels_key: str):
        key = (target, metric, labels_key)
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < self.cache_seconds:
            return hit[1]
        stats = self.compute(target, metric, labels_key)
        self._cache[key] = (time.monotonic(), stats)
        return stats

    def compute(self, target: str, metric: str, labels_key: str):
        since = utcnow() - self.window
        with session_scope() as s:
            row = s.execute(
                select(func.count(MetricSample.value), func.avg(MetricSample.value),
                       func.avg(MetricSample.value * MetricSample.value))
                .where(MetricSample.target == target, MetricSample.name == metric,
                       MetricSample.labels_key == labels_key, MetricSample.ts >= since)
            ).one()
        n, mean, mean_sq = row
        if not n:
            return None
        var = max(float(mean_sq) - float(mean) ** 2, 0.0)
        return float(mean), math.sqrt(var), int(n)

    def describe(self, target: str, metric: str, labels_key: str = "") -> dict:
        stats = self.compute(target, metric, labels_key)
        if not stats:
            return {"samples": 0}
        mean, std, n = stats
        return {"mean": round(mean, 3), "std": round(std, 3), "samples": n, "window_days": self.window.days}
