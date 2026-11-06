# Runbook: Snowflake warehouses: load, spill, cache, configuration and cost

Diagnostics: `engine_diagnostic` with `warehouse_config`, `spilling_queries`, `cache_and_pruning`,
`worst_pruning_queries`, `idle_and_cost`, `recent_queries`, `failed_tasks`, `copy_errors`;
`get_query_plan <query_id>` returns per-operator stats.

## Queuing (`wh_queued_queries` sustained, `queued_queries` high)
- More concurrent queries than the warehouse can run.
- Many small concurrent queries: add clusters (`set_warehouse_parameter MAX_CLUSTER_COUNT`; Enterprise edition).
  A bigger size does not add concurrency much.
- A few heavy queries hogging it: move them to their own warehouse (recommendation).
- `wh_multicluster_at_max`: already at the cluster limit and still queuing. Raise MAX_CLUSTER_COUNT or split workloads.
- `resize_warehouse` helps when individual queries are big and slow, not for concurrency.

## Spillage (`wh_local_spill_gb_1h`, `wh_remote_spill_gb_1h`)
- Local spill: working set exceeded warehouse memory and went to local SSD. An early warning; moderate slowdown.
- Remote spill: exceeded local disk too and went to cloud storage. Large slowdown and cost.
- Find the queries with `spilling_queries`, then `get_query_plan` on the worst one.
- Fix order: (1) cut data scanned (filters, pruning); (2) fix exploding joins (operator output rows far above input)
  or huge sorts / window functions over unfiltered data; (3) only then size up one step (`resize_warehouse`).
  Sizing up doubles memory and doubles credit rate. It is often cheaper overall if it removes remote spill.

## Cache reuse (`wh_cache_hit_pct_24h` low)
- Warehouse (local disk) cache keeps recently read micro-partitions while the warehouse stays running.
  It is dropped when the warehouse suspends.
- Low reuse with repeated reads of the same tables usually means AUTO_SUSPEND is so short that the cache is lost between
  bursts. Trade-off: longer AUTO_SUSPEND = more warm cache but more idle credits. Check `idle_and_cost` before changing.
- Low reuse on genuinely one-off scans (ELT over new data) is normal. Recommend no change.
- Result cache (identical query, unchanged data, 24 h) is separate and needs no warehouse.

## Pruning (`wh_poor_pruning_queries_24h`)
- Queries scanning 80%+ of partitions on tables with 1000+ partitions. Get examples with `worst_pruning_queries`.
- Causes: filters on columns uncorrelated with load order, functions wrapped around filter columns, or no filter.
- Fixes (recommendations): filter on naturally ordered columns (dates), avoid wrapping filter columns in functions,
  clustering keys for very large, frequently filtered tables (clustering costs credits to maintain), search
  optimization for point lookups.

## Idle credits (`wh_idle_credit_pct_24h`)
- Compute billed while no query ran: mostly the AUTO_SUSPEND tail after the last query, plus the 60-second minimum
  per resume. Uses 8-32 h old data because query attribution lags.
- Fix: lower AUTO_SUSPEND (`set_warehouse_parameter AUTO_SUSPEND 60..300`) for bursty/BI warehouses, and weigh it
  against the cache section above. Check for something that keeps resuming it (e.g. a frequent task or
  dashboard refresh polling).

## Configuration audit
- `wh_auto_suspend_seconds` > 600 or never: idle burn. Typical: 60 s for ELT/ad hoc, 300-600 s for BI with cache reuse.
- `wh_auto_resume_off`: queries fail with "warehouse suspended" until someone resumes it.
  `set_warehouse_parameter AUTO_RESUME TRUE`.
- `wh_statement_timeout_seconds` > 4 h: Snowflake's default is 172800 s (2 days); a runaway query can burn 2 days of
  credits. Set a warehouse-level cap (`STATEMENT_TIMEOUT_IN_SECONDS`, e.g. 3600-14400 depending on workload).
- `wh_no_resource_monitor` / `rm_no_suspend`: no hard credit cap. Recommend a resource monitor with SUSPEND at 100%
  (and NOTIFY at 80-90%). Creating monitors requires ACCOUNTADMIN and is a recommendation, not an action.
- `rm_used_pct` >= 90: the warehouse may be suspended soon. Confirm whether usage is expected before raising quota.

## Cloud services (`cloud_services_pct_1d` > 10)
- Cloud services are free up to 10% of daily compute; above that they are billed.
- Typical causes: very frequent tiny queries/metadata calls, heavy SHOW/INFORMATION_SCHEMA polling, complex
  compilation, many COPY commands with small files. Use `idle_and_cost` for the trend.

## Long-running queries
- `get_query_plan` with the query_id: look for TableScan with poor pruning, CartesianJoin, spill.
- `cancel_query` if it blocks a pipeline and the owner agrees.

## Credit spikes (`warehouse_credits_1h` anomaly)
- Compare with `idle_and_cost` and `recent_queries`. Typical causes: AUTO_SUSPEND too high, a new scheduled task,
  an oversized warehouse, a runaway retry loop. `suspend_warehouse` stops the burn immediately (running queries finish).

## Task / pipe failures
- `failed_tasks` / `copy_errors`. Common causes: dropped/renamed object, privilege change, schema drift.
