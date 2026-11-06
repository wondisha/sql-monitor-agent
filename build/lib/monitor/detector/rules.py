"""Deterministic detection. No LLM here: rules decide what is an incident."""
from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Callable

from ..adapters.base import Metric

_OPS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le,
    "==": operator.eq, "!=": operator.ne,
}
SEVERITIES = ("P1", "P2", "P3", "P4")


@dataclass
class Rule:
    id: str
    metric: str
    severity: str
    title: str
    engines: list[str] = field(default_factory=lambda: ["any"])
    type: str = "threshold"          # threshold | anomaly
    op: str = ">"
    threshold: float = 0.0
    for_cycles: int = 1
    z_score: float = 3.0
    min_samples: int = 50

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        r = cls(
            id=d["id"], metric=d["metric"], severity=d.get("severity", "P3").upper(),
            title=d.get("title", d["id"]), engines=[e.lower() for e in d.get("engines", ["any"])],
            type=d.get("type", "threshold"), op=d.get("op", ">"), threshold=float(d.get("threshold", 0)),
            for_cycles=int(d.get("for_cycles", 1)), z_score=float(d.get("z_score", 3)),
            min_samples=int(d.get("min_samples", 50)),
        )
        if r.severity not in SEVERITIES:
            raise ValueError(f"rule {r.id}: severity must be one of {SEVERITIES}")
        if r.type == "threshold" and r.op not in _OPS:
            raise ValueError(f"rule {r.id}: unsupported op {r.op}")
        return r

    def applies_to(self, engine: str) -> bool:
        return "any" in self.engines or engine in self.engines


@dataclass
class Event:
    target: str
    engine: str
    rule: Rule
    metric: Metric
    detail: dict = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return f"{self.target}|{self.rule.id}|{self.metric.labels_key}"


# (target, metric, labels_key) -> (mean, std, n) or None
BaselineFn = Callable[[str, str, str], "tuple[float, float, int] | None"]


class RuleEngine:
    def __init__(self, rules: list[Rule], baseline: BaselineFn | None = None):
        self.rules = rules
        self.baseline = baseline
        self._streak: dict[str, int] = {}

    @classmethod
    def from_config(cls, rule_dicts: list[dict], baseline: BaselineFn | None = None) -> "RuleEngine":
        return cls([Rule.from_dict(d) for d in rule_dicts], baseline)

    def evaluate(self, target: str, engine: str, metrics: list[Metric]) -> list[Event]:
        events: list[Event] = []
        for rule in self.rules:
            if not rule.applies_to(engine):
                continue
            for m in metrics:
                if m.name != rule.metric:
                    continue
                key = f"{target}|{rule.id}|{m.labels_key}"
                breached, detail = self._check(rule, target, m)
                if not breached:
                    self._streak.pop(key, None)
                    continue
                self._streak[key] = self._streak.get(key, 0) + 1
                if self._streak[key] >= rule.for_cycles:
                    detail["consecutive_breaches"] = self._streak[key]
                    events.append(Event(target, engine, rule, m, detail))
        return events

    def _check(self, rule: Rule, target: str, m: Metric) -> tuple[bool, dict]:
        if rule.type == "anomaly":
            if self.baseline is None:
                return False, {}
            stats = self.baseline(target, m.name, m.labels_key)
            if not stats:
                return False, {}
            mean, std, n = stats
            if n < rule.min_samples or std <= 0:
                return False, {}
            z = (m.value - mean) / std
            return z >= rule.z_score, {"value": m.value, "baseline_mean": round(mean, 3),
                                        "baseline_std": round(std, 3), "z_score": round(z, 2), "samples": n}
        ok = _OPS[rule.op](m.value, rule.threshold)
        return ok, {"value": m.value, "op": rule.op, "threshold": rule.threshold}
