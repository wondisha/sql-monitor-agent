"""SQL guard for anything the AI agent asks to run.

Two levels:
  validate_diagnostic(sql, engine)  - SELECT/SHOW against SYSTEM views only. The agent never reads business data.
  assert_select_only(sql, engine)   - a single side-effect-free SELECT on any table; used only for EXPLAIN
                                      (planned, never executed).
Both reject DML/DDL, multiple statements, SELECT INTO, and side-effecting or exfiltrating functions.
Database-side read-only roles and read-only sessions are the second line of defence.
"""
from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

DIALECT = {"postgres": "postgres", "mysql": "mysql", "mssql": "tsql", "snowflake": "snowflake"}


class SQLGuardError(ValueError):
    pass


_FORBIDDEN_NODES = tuple(
    getattr(exp, n) for n in (
        "Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter", "TruncateTable", "Command",
        "Into", "Grant", "Revoke", "Copy", "Set", "Use", "Transaction", "Commit", "Rollback", "Pragma",
        "LoadData", "Kill", "Execute",
    ) if hasattr(exp, n)
)

_FORBIDDEN_FUNC = re.compile(
    r"^(pg_(read|ls|stat_file|file|terminate|cancel|reload|rotate|create|switch|advisory|sleep|promote|"
    r"wal_replay|drop|replication|logical|backup|start|stop|import|export)|lo_|dblink|query_to|table_to|cursor_to|"
    r"schema_to|database_to|set_config|nextval|setval|currval|txid_|xp_|sp_|openrowset|openquery|opendatasource|"
    r"openxml|sleep|benchmark|get_lock|release_lock|load_file|sys_exec|sys_eval|exec|execute|call|eval|"
    r"result_scan|system\$(?!clustering_information|clustering_depth|estimate_|explain_|typeof|get_tag))",
    re.IGNORECASE,
)

# SHOW commands allowed for the agent (all are metadata-only).
_SHOW_ALLOWED = {
    "snowflake": re.compile(r"^SHOW\s+(WAREHOUSES|LOCKS|TRANSACTIONS|TASKS|PIPES|GRANTS|PARAMETERS|ROLES|"
                            r"RESOURCE\s+MONITORS|USERS|DATABASES|SCHEMAS|TABLES|VIEWS|STAGES|STREAMS|INTEGRATIONS)\b",
                            re.IGNORECASE),
    "mysql": re.compile(r"^SHOW\s+(GLOBAL\s+STATUS|GLOBAL\s+VARIABLES|STATUS|VARIABLES|FULL\s+PROCESSLIST|PROCESSLIST|"
                        r"ENGINE\s+INNODB\s+STATUS|REPLICA\s+STATUS|SLAVE\s+STATUS|MASTER\s+STATUS|BINARY\s+LOGS|"
                        r"INDEX(ES)?\s+FROM|CREATE\s+TABLE|TABLE\s+STATUS|OPEN\s+TABLES)\b", re.IGNORECASE),
    "postgres": re.compile(r"^SHOW\s+\w+\s*$", re.IGNORECASE),
    "mssql": re.compile(r"^$a"),  # SHOW does not exist in T-SQL
}

# Snowflake table functions the agent may call (INFORMATION_SCHEMA or built-in).
_SF_TABLE_FUNCS = {
    "QUERY_HISTORY", "QUERY_HISTORY_BY_USER", "QUERY_HISTORY_BY_WAREHOUSE", "QUERY_HISTORY_BY_SESSION",
    "WAREHOUSE_LOAD_HISTORY", "WAREHOUSE_METERING_HISTORY", "TASK_HISTORY", "LOGIN_HISTORY",
    "LOGIN_HISTORY_BY_USER", "COPY_HISTORY", "PIPE_USAGE_HISTORY", "AUTOMATIC_CLUSTERING_HISTORY",
    "GET_QUERY_OPERATOR_STATS", "SERVERLESS_TASK_HISTORY", "DATABASE_STORAGE_USAGE_HISTORY",
    "STAGE_STORAGE_USAGE_HISTORY", "MATERIALIZED_VIEW_REFRESH_HISTORY", "DYNAMIC_TABLE_REFRESH_HISTORY",
}
_PG_TABLE_FUNCS = {"PG_STAT_STATEMENTS", "PG_LOCK_STATUS", "PG_STAT_GET_ACTIVITY", "UNNEST", "GENERATE_SERIES",
                   "PG_BLOCKING_PIDS", "PG_SETTINGS", "PG_SHOW_ALL_SETTINGS"}
_MSSQL_TABLE_FUNCS = {"DM_EXEC_SQL_TEXT", "DM_EXEC_QUERY_PLAN", "DM_EXEC_TEXT_QUERY_PLAN", "DM_DB_INDEX_PHYSICAL_STATS",
                      "DM_EXEC_INPUT_BUFFER", "DM_DB_PARTITION_STATS", "FN_XE_FILE_TARGET_READ_FILE",
                      "DM_EXEC_PLAN_ATTRIBUTES", "DM_IO_VIRTUAL_FILE_STATS"}

_MSSQL_MSDB = {"SYSJOBS", "SYSJOBHISTORY", "SYSJOBSTEPS", "SYSJOBACTIVITY", "SYSJOBSCHEDULES", "SYSSCHEDULES",
               "BACKUPSET", "BACKUPMEDIAFAMILY", "RESTOREHISTORY"}


def _strip(sql: str) -> str:
    s = sql.strip()
    while s.endswith(";"):
        s = s[:-1].rstrip()
    if not s:
        raise SQLGuardError("empty statement")
    return s


def _parse_one(sql: str, engine: str) -> exp.Expression:
    try:
        trees = [t for t in sqlglot.parse(sql, read=DIALECT[engine]) if t is not None]
    except sqlglot.errors.ParseError as e:
        raise SQLGuardError(f"could not parse SQL: {str(e)[:300]}") from e
    if len(trees) != 1:
        raise SQLGuardError("exactly one statement is allowed")
    return trees[0]


def _check_common(tree: exp.Expression) -> None:
    if not isinstance(tree, (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)):
        raise SQLGuardError(f"only SELECT statements are allowed (got {type(tree).__name__})")
    for node in tree.walk():
        if isinstance(node, _FORBIDDEN_NODES):
            raise SQLGuardError(f"forbidden construct: {type(node).__name__}")
        if isinstance(node, exp.Func):
            name = node.name if isinstance(node, exp.Anonymous) else (node.sql_name() or "")
            if name and _FORBIDDEN_FUNC.match(name):
                raise SQLGuardError(f"forbidden function: {name}")
        if isinstance(node, exp.Lock):  # SELECT ... FOR UPDATE takes row locks
            raise SQLGuardError("locking clauses (FOR UPDATE/SHARE) are not allowed")


def assert_select_only(sql: str, engine: str) -> str:
    s = _strip(sql)
    tree = _parse_one(s, engine)
    _check_common(tree)
    return s


def _table_func_name(t: exp.Table) -> str | None:
    fn = t.this
    if isinstance(fn, exp.Dot):
        fn = fn.expression
    if isinstance(fn, exp.Func):
        return (fn.name if isinstance(fn, exp.Anonymous) else fn.sql_name()).upper()
    return None


def _table_allowed(t: exp.Table, engine: str, ctes: set[str]) -> bool:
    fn = _table_func_name(t)
    name, db, catalog = (t.name or "").upper(), (t.db or "").upper(), (t.catalog or "").upper()
    if fn:
        allowed = {"snowflake": _SF_TABLE_FUNCS, "postgres": _PG_TABLE_FUNCS, "mssql": _MSSQL_TABLE_FUNCS}.get(engine, set())
        return fn in allowed
    if not db and name.lower() in ctes:
        return True
    if engine == "postgres":
        return db in ("PG_CATALOG", "INFORMATION_SCHEMA") or (db in ("", "PUBLIC") and name.startswith("PG_"))
    if engine == "mysql":
        return db in ("PERFORMANCE_SCHEMA", "INFORMATION_SCHEMA", "SYS")
    if engine == "mssql":
        if db == "SYS" or (not db and name.startswith("DM_")):
            return True
        if db == "INFORMATION_SCHEMA":
            return True
        return catalog == "MSDB" and db in ("DBO", "") and name in _MSSQL_MSDB
    if engine == "snowflake":
        if db == "INFORMATION_SCHEMA":
            return True
        return catalog == "SNOWFLAKE" and db in ("ACCOUNT_USAGE", "ORGANIZATION_USAGE", "READER_ACCOUNT_USAGE")
    return False


def validate_diagnostic(sql: str, engine: str) -> str:
    """Return the cleaned statement if the agent may run it, else raise SQLGuardError."""
    if engine not in DIALECT:
        raise SQLGuardError(f"unknown engine {engine}")
    s = _strip(sql)
    if ";" in s:
        raise SQLGuardError("multiple statements are not allowed")

    if re.match(r"^\s*(SHOW|DESC|DESCRIBE)\b", s, re.IGNORECASE):
        if re.match(r"^\s*(DESC|DESCRIBE)\b", s, re.IGNORECASE) and engine == "snowflake" and \
                re.match(r"^\s*DESC(RIBE)?\s+(WAREHOUSE|USER|TASK|PIPE)\b", s, re.IGNORECASE):
            return s
        if _SHOW_ALLOWED[engine].match(s.strip()):
            return s
        raise SQLGuardError("this SHOW/DESCRIBE command is not on the allowlist")

    if re.match(r"^\s*EXPLAIN\b", s, re.IGNORECASE):
        raise SQLGuardError("use the get_query_plan tool for EXPLAIN")

    tree = _parse_one(s, engine)
    _check_common(tree)
    ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    for t in tree.find_all(exp.Table):
        if not _table_allowed(t, engine, ctes):
            raise SQLGuardError(
                f"table {t.sql(dialect=DIALECT[engine])} is not a system/monitoring view; "
                "the agent may only read engine metadata, never business tables")
    return s
