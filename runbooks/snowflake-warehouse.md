# Runbook: Snowflake warehouse queuing, spilling and credit spikes

## Queuing (`warehouse_queued_load` > 0, `queued_queries` high)
- Means more concurrent queries than the warehouse can run. Check `get_wait_stats` (running vs queued load).
- Short bursts of many small queries: increase concurrency with a **multi-cluster** warehouse (MAX_CLUSTER_COUNT)
  rather than a larger size. That is a recommendation (not an allowlisted action).
- A few heavy queries hogging the warehouse: move them to a separate warehouse.
- `resize_warehouse` helps only when individual queries are big and slow. It doesn't help with concurrency.

## Spilling (`remote_spill_gb_1h` > 1)
- `bytes_spilled_to_remote_storage` means the query's working set didn't fit in memory or local disk.
- Fix order: (1) reduce data scanned (filters, clustering, pruning: compare partitions_scanned vs partitions_total);
  (2) fix exploding joins (check `get_query_plan` operator stats for a join whose output rows are much larger than its input rows);
  (3) only then size up the warehouse one step.

## Long-running queries
- `get_query_plan` with the query_id returns operator stats. Look for TableScan with poor pruning,
  CartesianJoin, or high `bytes spilled`.
- `cancel_query` if it blocks a pipeline and the owner agrees.

## Credit spikes (`warehouse_credits_1h` anomaly)
- Compare `engine_diagnostic warehouse_credits_7d`. Typical causes: AUTO_SUSPEND set too high or disabled, a new
  scheduled task, an oversized warehouse, a runaway retry loop.
- `suspend_warehouse` stops burn immediately; queued queries wait until it resumes.

## Task / pipe failures
- `engine_diagnostic failed_tasks` / `copy_errors`. Common causes: dropped/renamed object, privilege change, schema drift
  in source files.
