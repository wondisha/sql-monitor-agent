# Runbook: replication lag, connections, bloat, tempdb, deadlocks

## Replication lag (`replication_lag_seconds`)
- PostgreSQL replica: long-running queries on the replica conflict with replay (check `hot_standby_feedback`,
  `max_standby_streaming_delay`); heavy write bursts on the primary; network.
- MySQL: `SHOW REPLICA STATUS`. A NULL lag value means the SQL or IO thread stopped (check Last_SQL_Error).
  Large single transactions replay slowly.
- SQL Server AG: check redo queue / log send queue in `sys.dm_hadr_database_replica_states`.

## Connections near max (`connection_pct`)
- Group sessions by application/user (`get_active_sessions`). Usually a pool leak or a pool sized above what the
  database can handle. Fix in the app or add PgBouncer/ProxySQL. Killing sessions only buys time.

## Table bloat (`max_dead_tuple_pct`, PostgreSQL)
- Autovacuum is blocked by a long transaction (check `idle_in_txn_max_seconds`) or tuned too lazily for a hot table.
  `analyze_table` refreshes stats only; VACUUM is a DBA task.

## tempdb low (SQL Server)
- Find sessions with big spills/sorts (`get_top_queries` spills column). Version store growth means a long
  snapshot transaction.

## Deadlocks
- SQL Server: `engine_diagnostic recent_deadlocks` returns the XML graph. Look for two procedures that access
  the same tables in opposite order.
- PostgreSQL/MySQL: the server log has the details. Fix by consistent lock ordering and shorter transactions.
