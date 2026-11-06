"""Configuration loading with ${VAR} / ${VAR:-default} environment expansion."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return _expand(yaml.safe_load(f) or {})


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader (does not override variables already set)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


@dataclass
class Target:
    name: str
    engine: str
    monitor: dict
    executor: dict
    enabled: bool = True
    limits: dict = field(default_factory=dict)
    source: str = "config"   # "config" = config/targets.yaml (hand-edited), "ui" = added from the dashboard


@dataclass
class Settings:
    raw: dict
    base_dir: Path
    targets: list[Target]
    rules: list[dict]
    governance: dict

    @property
    def state_db_url(self) -> str:
        return self.raw.get("state_db_url") or "sqlite:///monitor_state.db"

    def section(self, name: str) -> dict:
        return self.raw.get(name, {}) or {}

    def target(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(f"Unknown target: {name}")

    @property
    def runbooks_dir(self) -> Path:
        return self.base_dir / self.raw.get("runbooks_dir", "runbooks")


def target_from_dict(t: dict, source: str = "config") -> Target:
    return Target(
        name=t["name"], engine=t["engine"].lower(), monitor=t.get("monitor", {}) or {},
        executor=t.get("executor", {}) or {}, enabled=bool(t.get("enabled", True)),
        limits=t.get("limits", {}) or {}, source=source,
    )


def load_settings(settings_path: str | Path = "config/settings.yaml") -> Settings:
    settings_path = Path(settings_path).resolve()
    base_dir = settings_path.parent.parent
    load_dotenv(base_dir / ".env")
    raw = load_yaml(settings_path)

    targets: list[Target] = []
    sources = [(base_dir / raw.get("targets_file", "config/targets.yaml"), "config"),
               (base_dir / raw.get("ui_targets_file", "config/targets_ui.yaml"), "ui")]
    for path, source in sources:
        if not path.exists():
            continue
        for t in load_yaml(path).get("targets", []) or []:
            if any(x.name == t["name"] for x in targets):
                raise ValueError(f"duplicate target name {t['name']!r} in {path.name}")
            targets.append(target_from_dict(t, source))

    rules: list[dict] = []
    rules_dir = base_dir / raw.get("rules_dir", "config/rules")
    if rules_dir.exists():
        for f in sorted(rules_dir.glob("*.yaml")):
            rules.extend(load_yaml(f).get("rules", []))

    gov_path = base_dir / raw.get("governance_file", "config/governance.yaml")
    governance = load_yaml(gov_path) if gov_path.exists() else {}

    return Settings(raw=raw, base_dir=base_dir, targets=targets, rules=rules, governance=governance)
