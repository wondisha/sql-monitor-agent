import pytest

from monitor.agent.sql_guard import SQLGuardError, assert_select_only, validate_diagnostic

ALLOWED = [
    ("postgres", "SELECT pid, query FROM pg_stat_activity"),
    ("postgres", "WITH x AS (SELECT * FROM pg_stat_activity) SELECT * FROM x"),
    ("postgres", "SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 5"),
    ("postgres", "SELECT * FROM pg_catalog.pg_locks;"),
    ("mysql", "SELECT * FROM performance_schema.events_statements_summary_by_digest"),
    ("mysql", "SHOW ENGINE INNODB STATUS"),
    ("mssql", "SELECT TOP 10 * FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t"),
    ("mssql", "SELECT * FROM msdb.dbo.sysjobhistory"),
    ("snowflake", "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY LIMIT 10"),
    ("snowflake", "SELECT * FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY(RESULT_LIMIT => 100))"),
    ("snowflake", "SHOW WAREHOUSES"),
]

DENIED = [
    ("postgres", "SELECT * FROM customers"),                       # business data
    ("postgres", "SELECT * FROM (SELECT * FROM public.orders) s"),  # business data in subquery
    ("postgres", "SELECT pg_terminate_backend(123)"),              # side effect
    ("postgres", "SELECT query_to_xml('select * from customers', true, true, '')"),  # query smuggling
    ("postgres", "DELETE FROM pg_stat_activity"),
    ("postgres", "SELECT 1; DROP TABLE x"),
    ("postgres", "SELECT * INTO newt FROM pg_stat_activity"),
    ("postgres", "SELECT * FROM pg_stat_activity FOR UPDATE"),
    ("postgres", "EXPLAIN ANALYZE DELETE FROM t"),
    ("mysql", "SELECT * FROM mysql.user"),
    ("mysql", "SELECT SLEEP(10) FROM sys.processlist"),
    ("mysql", "SHOW GRANTS FOR root"),
    ("mssql", "SELECT * FROM dbo.Orders"),
    ("mssql", "SELECT * FROM OPENROWSET('SQLNCLI','x','select 1')"),
    ("mssql", "EXEC xp_cmdshell 'dir'"),
    ("snowflake", "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))"),
    ("snowflake", "SELECT SYSTEM$CANCEL_QUERY('x')"),
    ("snowflake", "SELECT * FROM SALES.PUBLIC.ORDERS"),
    ("snowflake", "CREATE TABLE x AS SELECT 1"),
    ("snowflake", "ALTER WAREHOUSE wh SET WAREHOUSE_SIZE = 'X6LARGE'"),
]


@pytest.mark.parametrize("engine,sql", ALLOWED)
def test_allowed(engine, sql):
    assert validate_diagnostic(sql, engine)


@pytest.mark.parametrize("engine,sql", DENIED)
def test_denied(engine, sql):
    with pytest.raises(SQLGuardError):
        validate_diagnostic(sql, engine)


def test_select_only_allows_business_tables_for_explain():
    assert assert_select_only("SELECT * FROM orders WHERE id = $1", "postgres")


@pytest.mark.parametrize("sql", ["UPDATE orders SET x = 1", "SELECT pg_sleep(100)", "SELECT 1; SELECT 2"])
def test_select_only_rejects_side_effects(sql):
    with pytest.raises(SQLGuardError):
        assert_select_only(sql, "postgres")
