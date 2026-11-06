"""The ONLY write operations this system can perform, each with strict parameter validation.

The agent proposes {type, params}. It never supplies raw SQL to the executor: SQL is rendered here from
validated parameters, so a malicious or confused proposal cannot smuggle in other statements.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,254}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SF_SIZES = ["XSMALL", "SMALL", "MEDIUM", "LARGE", "XLARGE", "XXLARGE", "XXXLARGE", "X4LARGE", "X5LARGE", "X6LARGE"]
_SF_SIZE_ALIASES = {"X-SMALL": "XSMALL", "XS": "XSMALL", "S": "SMALL", "M": "MEDIUM", "L": "LARGE", "XL": "XLARGE",
                    "X-LARGE": "XLARGE", "2X-LARGE": "XXLARGE", "2XLARGE": "XXLARGE", "3X-LARGE": "XXXLARGE",
                    "3XLARGE": "XXXLARGE", "4X-LARGE": "X4LARGE", "4XLARGE": "X4LARGE", "5XLARGE": "X5LARGE",
                    "6XLARGE": "X6LARGE"}


class ActionError(ValueError):
    pass


@dataclass
class Rendered:
    sql: str                       # human-readable statement (shown for approval)
    bind_sql: str                  # statement passed to the driver
    params: tuple | None = None
    executable: bool = True        # False -> script only, never run by the executor


@dataclass
class ActionSpec:
    type: str
    engines: tuple[str, ...]
    risk: str
    description: str
    render: Callable[[str, dict, dict], Rendered]
    rollback: str = ""


def _int(params: dict, key: str) -> int:
    try:
        v = int(str(params[key]).strip())
    except (KeyError, ValueError):
        raise ActionError(f"parameter '{key}' must be an integer") from None
    if v <= 0:
        raise ActionError(f"parameter '{key}' must be positive")
    return v


def _ident(value: str, what: str) -> str:
    v = str(value).strip().strip('"').strip("`").strip("[]")
    if not _IDENT.match(v):
        raise ActionError(f"invalid {what}: {value!r}")
    return v


def _qualified(name: str) -> list[str]:
    parts = [p for p in str(name).split(".") if p]
    if not 1 <= len(parts) <= 3:
        raise ActionError(f"invalid table name: {name!r}")
    return [_ident(p, "identifier") for p in parts]


def _quote(engine: str, parts: list[str]) -> str:
    if engine == "mysql":
        return ".".join(f"`{p}`" for p in parts)
    if engine == "mssql":
        return ".".join(f"[{p}]" for p in parts)
    return ".".join(f'"{p}"' for p in parts)


# ---- renderers -----------------------------------------------------------------------
def _kill_session(engine: str, p: dict, limits: dict) -> Rendered:
    if engine == "snowflake":
        qid = str(p.get("query_id") or p.get("session_id") or "").strip()
        if not _UUID.match(qid):
            raise ActionError("Snowflake kill/cancel needs a query_id (UUID)")
        return Rendered(f"SELECT SYSTEM$CANCEL_QUERY('{qid}')", "SELECT SYSTEM$CANCEL_QUERY(%s)", (qid,))
    sid = _int(p, "session_id")
    if engine == "postgres":
        return Rendered(f"SELECT pg_terminate_backend({sid})", "SELECT pg_terminate_backend(%s)", (sid,))
    if engine == "mysql":
        return Rendered(f"KILL {sid}", f"KILL {sid}")
    if engine == "mssql":
        if sid <= 50:
            raise ActionError("refusing to KILL a system session (session_id <= 50)")
        return Rendered(f"KILL {sid}", f"KILL {sid}")
    raise ActionError(f"kill_session not supported on {engine}")


def _cancel_query(engine: str, p: dict, limits: dict) -> Rendered:
    if engine == "postgres":
        sid = _int(p, "session_id")
        return Rendered(f"SELECT pg_cancel_backend({sid})", "SELECT pg_cancel_backend(%s)", (sid,))
    if engine == "mysql":
        sid = _int(p, "session_id")
        return Rendered(f"KILL QUERY {sid}", f"KILL QUERY {sid}")
    return _kill_session(engine, p, limits)


def _norm_size(size: str) -> str:
    s = str(size).strip().upper().replace("_", "")
    s = _SF_SIZE_ALIASES.get(s, s)
    if s not in SF_SIZES:
        raise ActionError(f"invalid warehouse size {size!r}; use one of {SF_SIZES}")
    return s


def _resize_warehouse(engine: str, p: dict, limits: dict) -> Rendered:
    wh = _ident(p.get("warehouse", ""), "warehouse name")
    size = _norm_size(p.get("size", ""))
    cap = _norm_size(limits.get("max_warehouse_size", "LARGE"))
    if SF_SIZES.index(size) > SF_SIZES.index(cap):
        raise ActionError(f"size {size} exceeds the configured max_warehouse_size {cap}")
    sql = f"ALTER WAREHOUSE \"{wh}\" SET WAREHOUSE_SIZE = '{size}'"
    return Rendered(sql, sql)


def _suspend_warehouse(engine: str, p: dict, limits: dict) -> Rendered:
    wh = _ident(p.get("warehouse", ""), "warehouse name")
    sql = f'ALTER WAREHOUSE "{wh}" SUSPEND'
    return Rendered(sql, sql)


def _analyze_table(engine: str, p: dict, limits: dict) -> Rendered:
    parts = _qualified(p.get("table", ""))
    q = _quote(engine, parts)
    sql = {"postgres": f"ANALYZE {q}", "mysql": f"ANALYZE TABLE {q}", "mssql": f"UPDATE STATISTICS {q}"}.get(engine)
    if not sql:
        raise ActionError(f"analyze_table not supported on {engine}")
    return Rendered(sql, sql)


def _create_index_script(engine: str, p: dict, limits: dict) -> Rendered:
    parts = _qualified(p.get("table", ""))
    cols = p.get("columns") or []
    if isinstance(cols, str):
        cols = [c.strip() for c in cols.split(",")]
    cols = [_ident(c, "column") for c in cols if c]
    if not cols:
        raise ActionError("create_index_script needs at least one column")
    include = [_ident(c, "column") for c in (p.get("include") or [])]
    name = _ident(p.get("index_name") or f"ix_{parts[-1]}_{'_'.join(cols)}"[:60], "index name")
    q = _quote(engine, parts)
    collist = ", ".join(_quote(engine, [c]) for c in cols)
    if engine == "postgres":
        sql = f'CREATE INDEX CONCURRENTLY "{name}" ON {q} ({collist})'
        if include:
            sql += " INCLUDE (" + ", ".join(_quote(engine, [c]) for c in include) + ")"
    elif engine == "mssql":
        sql = f"CREATE NONCLUSTERED INDEX [{name}] ON {q} ({collist})"
        if include:
            sql += " INCLUDE (" + ", ".join(_quote(engine, [c]) for c in include) + ")"
        sql += " WITH (ONLINE = ON)"
    elif engine == "mysql":
        sql = f"ALTER TABLE {q} ADD INDEX `{name}` ({collist}), ALGORITHM=INPLACE, LOCK=NONE"
    else:
        raise ActionError(f"create_index_script not supported on {engine}")
    return Rendered(sql + ";", sql, executable=False)


ACTIONS: dict[str, ActionSpec] = {
    "kill_session": ActionSpec("kill_session", ("postgres", "mysql", "mssql", "snowflake"), "medium",
                               "Terminate a session (rolls back its open transaction)", _kill_session,
                               "None - the client must reconnect; its uncommitted work is rolled back."),
    "cancel_query": ActionSpec("cancel_query", ("postgres", "mysql", "mssql", "snowflake"), "low",
                               "Cancel the running statement but keep the session", _cancel_query,
                               "None - the client can re-run the statement."),
    "resize_warehouse": ActionSpec("resize_warehouse", ("snowflake",), "medium",
                                   "Change a Snowflake warehouse size (bounded by limits.max_warehouse_size)",
                                   _resize_warehouse, "ALTER WAREHOUSE back to the previous size."),
    "suspend_warehouse": ActionSpec("suspend_warehouse", ("snowflake",), "medium",
                                    "Suspend a Snowflake warehouse (running queries finish first)",
                                    _suspend_warehouse, "ALTER WAREHOUSE ... RESUME"),
    "analyze_table": ActionSpec("analyze_table", ("postgres", "mysql", "mssql"), "low",
                                "Refresh optimizer statistics for one table", _analyze_table,
                                "None needed; statistics are refreshed again by autovacuum/auto-stats."),
    "create_index_script": ActionSpec("create_index_script", ("postgres", "mysql", "mssql"), "high",
                                      "Generate a CREATE INDEX script for a DBA (never executed automatically)",
                                      _create_index_script, "DROP INDEX <name>"),
}


def render_action(action_type: str, engine: str, params: dict, limits: dict | None = None) -> tuple[ActionSpec, Rendered]:
    spec = ACTIONS.get(action_type)
    if spec is None:
        raise ActionError(f"action type {action_type!r} is not on the allowlist: {sorted(ACTIONS)}")
    if engine not in spec.engines:
        raise ActionError(f"{action_type} is not supported on {engine}")
    return spec, spec.render(engine, params or {}, limits or {})
