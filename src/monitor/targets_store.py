"""Servers added from the dashboard.

- Connection details go to config/targets_ui.yaml (no secrets in it).
- Passwords go to .env as MON_<NAME>_<ROLE>_PASSWORD and are referenced from the YAML as ${VAR}.
- config/targets.yaml (hand-edited, with comments) is never rewritten.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import yaml

from .config import Settings, Target

_LOCK = threading.Lock()
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
SECRET_FIELDS = {"password", "private_key_passphrase"}

# Field schema per engine: (key, label, kind, default, required). kind: text | number | password | bool | select
ENGINE_FIELDS: dict[str, list[tuple]] = {
    "postgres": [("host", "Host", "text", "", True), ("port", "Port", "number", 5432, True),
                 ("dbname", "Database", "text", "postgres", True),
                 ("sslmode", "SSL mode", "select:disable,prefer,require,verify-full", "prefer", False)],
    "mysql": [("host", "Host", "text", "", True), ("port", "Port", "number", 3306, True),
              ("database", "Default database (optional)", "text", "", False)],
    "mssql": [("server", "Server (host,port)", "text", "", True),
              ("database", "Database", "text", "master", True),
              ("driver", "ODBC driver", "text", "ODBC Driver 18 for SQL Server", True),
              ("trust_server_certificate", "Trust server certificate", "bool", True, False)],
    "snowflake": [("account", "Account identifier (orgname-account)", "text", "", True),
                  ("warehouse", "Warehouse (XS recommended)", "text", "MONITOR_WH", True),
                  ("database", "Database (any, for INFORMATION_SCHEMA)", "text", "MONITOR_DB", True)],
}
# Login fields, asked separately for the monitor (read-only) and executor (approved actions) logins.
LOGIN_FIELDS: dict[str, list[tuple]] = {
    "snowflake": [("user", "User", "text", "", True), ("role", "Role", "text", "", True),
                  ("private_key_path", "Private key file path (.p8)", "text", "", False),
                  ("private_key_passphrase", "Key passphrase (only if the key is encrypted)", "password", "", False),
                  ("password", "Password (if not using a key)", "password", "", False)],
    "_default": [("user", "User", "text", "", True), ("password", "Password", "password", "", False)],
}


class TargetFormError(ValueError):
    pass


def schema() -> dict:
    def fields(lst):
        return [{"key": k, "label": lab, "kind": kind, "default": d, "required": r} for k, lab, kind, d, r in lst]
    return {e: {"connection": fields(f), "login": fields(LOGIN_FIELDS.get(e, LOGIN_FIELDS["_default"]))}
            for e, f in ENGINE_FIELDS.items()}


def _ui_path(settings: Settings) -> Path:
    return settings.base_dir / settings.raw.get("ui_targets_file", "config/targets_ui.yaml")


def _env_var(name: str, role: str, key: str) -> str:
    return f"MON_{re.sub(r'[^A-Z0-9]', '_', name.upper())}_{role.upper()}_{key.upper()}"


def build(settings: Settings, form: dict, *, for_test: bool = False) -> tuple[Target, dict, dict]:
    """Validate a form submission.

    Returns (target with real secrets for connecting, yaml dict with ${VAR} refs, {VAR: secret}).
    """
    name = str(form.get("name", "")).strip().lower()
    engine = str(form.get("engine", "")).strip().lower()
    if engine not in ENGINE_FIELDS:
        raise TargetFormError(f"engine must be one of {sorted(ENGINE_FIELDS)}")
    if not NAME_RE.match(name):
        raise TargetFormError("name: 2-63 chars, lowercase letters, digits, '-' or '_'")
    if not for_test and any(t.name == name for t in settings.targets):
        raise TargetFormError(f"a target named {name!r} already exists")

    conn: dict = {}
    for key, label, kind, default, required in ENGINE_FIELDS[engine]:
        val = (form.get("connection") or {}).get(key, default)
        if kind == "number":
            try:
                val = int(val)
            except (TypeError, ValueError):
                raise TargetFormError(f"{label} must be a number") from None
        elif kind == "bool":
            val = val in (True, "true", "on", "1", 1)
        else:
            val = str(val or "").strip()
        if required and val in ("", None):
            raise TargetFormError(f"{label} is required")
        if val not in ("", None):
            conn[key] = val

    real: dict = {}
    stored: dict = {}
    secrets: dict = {}
    for role in ("monitor", "executor"):
        login = form.get(role) or {}
        if role == "executor" and not str(login.get("user", "")).strip():
            real[role], stored[role] = {}, {}          # executor is optional: actions just won't run
            continue
        r, s = dict(conn), dict(conn)
        for key, label, kind, default, required in LOGIN_FIELDS.get(engine, LOGIN_FIELDS["_default"]):
            val = str(login.get(key, "") or "").strip()
            if required and not val:
                raise TargetFormError(f"{role} {label.lower()} is required")
            if not val:
                continue
            r[key] = val
            if key in SECRET_FIELDS:
                var = _env_var(name, role, key)
                secrets[var] = val
                s[key] = "${" + var + "}"
            else:
                s[key] = val
        if engine == "snowflake" and not (r.get("private_key_path") or r.get("password")):
            raise TargetFormError(f"{role}: give a private key path or a password")
        if r.get("private_key_path") and not Path(r["private_key_path"]).exists():
            raise TargetFormError(f"{role}: key file not found: {r['private_key_path']}")
        real[role], stored[role] = r, s

    limits = {}
    if engine == "snowflake":
        limits["max_warehouse_size"] = str(form.get("max_warehouse_size") or "LARGE").upper()
    target = Target(name=name, engine=engine, monitor=real["monitor"], executor=real["executor"],
                    limits=limits, source="ui")
    yaml_entry = {"name": name, "engine": engine, "enabled": True, "monitor": stored["monitor"],
                  "executor": stored["executor"], **({"limits": limits} if limits else {})}
    return target, yaml_entry, secrets


def save(settings: Settings, yaml_entry: dict, secrets: dict) -> None:
    with _LOCK:
        _write_env(settings.base_dir / ".env", secrets)
        path = _ui_path(settings)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
        items = (data or {}).get("targets", []) or []
        items = [t for t in items if t.get("name") != yaml_entry["name"]] + [yaml_entry]
        _write_yaml(path, items)


def delete(settings: Settings, name: str) -> None:
    with _LOCK:
        path = _ui_path(settings)
        if not path.exists():
            raise TargetFormError("no dashboard-managed targets")
        items = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("targets", []) or []
        if not any(t.get("name") == name for t in items):
            raise TargetFormError(f"{name} was not added from the dashboard; edit config/targets.yaml instead")
        _write_yaml(path, [t for t in items if t.get("name") != name])
        exact = {_env_var(name, role, key) for role in ("monitor", "executor") for key in SECRET_FIELDS}
        _write_env(settings.base_dir / ".env", {}, remove_keys=exact)


def _write_yaml(path: Path, items: list) -> None:
    header = ("# Managed by the dashboard (Targets -> Add server). Passwords live in .env.\n"
              "# Hand-written targets belong in config/targets.yaml.\n")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(header + yaml.safe_dump({"targets": items}, sort_keys=False), encoding="utf-8")
    tmp.replace(path)


def _write_env(path: Path, values: dict, remove_keys: set[str] | None = None) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    out, seen = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key and remove_keys and key in remove_keys:
            os.environ.pop(key, None)
            continue
        if key in values:
            out.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in values.items() if k not in seen]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.environ.update(values)
