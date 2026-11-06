# Runbook: blocking and lock waits (PostgreSQL, MySQL, SQL Server)

## Symptoms
- `blocking_max_wait_seconds` high, `blocked_sessions` > 0, application timeouts.

## Diagnose
1. `get_blocking_chain`: find the head blocker (a blocker that is not itself blocked).
2. Look at the head blocker's state:
   - **idle in transaction** (PG) / **Sleeping with open_transaction_count > 0** (MSSQL) / an old `innodb_trx` row
     with no running query (MySQL): the application opened a transaction and forgot to commit. This is the most
     common cause.
   - **active**: a long statement (batch update, DDL, missing index on a FK) is holding locks while it runs.
3. Check the blocker's application_name / host / login to identify the owning service.
4. DDL (ALTER TABLE, CREATE INDEX without CONCURRENTLY/ONLINE) takes heavy locks and queues every other session.

## Fix
- Idle-in-transaction blocker: `kill_session` on the head blocker (its uncommitted work is rolled back).
- Active long statement: prefer `cancel_query` first; kill only if cancel fails.
- Never kill replication, backup or system sessions.

## Prevent
- PostgreSQL: `idle_in_transaction_session_timeout`, `lock_timeout` for migrations.
- MySQL: `innodb_lock_wait_timeout`, short transactions in the app.
- SQL Server: READ_COMMITTED_SNAPSHOT to stop readers blocking on writers.
- Fix connection-pool code paths that skip commit/rollback on exceptions.
