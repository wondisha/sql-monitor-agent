# SQL Monitor Agent

Agentic monitoring and troubleshooting for **Snowflake, PostgreSQL, MySQL and SQL Server**.

- **Detection is deterministic.** Collectors poll each engine's own telemetry and YAML rules open incidents. The
  LLM is never in the detection path: alerting keeps working without it, costs stay predictable, and every
  alert can be traced to a rule.
- **The AI investigates.** Each incident runs an investigation with Claude (`claude-opus-5-5`, adaptive thinking),
  using read-only tools only. The result is a structured root-cause analysis: summary, evidence, confidence and
  proposed actions.
- **Humans approve every change.** Proposed actions are rendered from an allowlist, previewed, and executed only
  after an approver clicks *Approve*. They run with separate privileged credentials, and every step is audited.
- **Snowflake user governance.** Users inactive for 90 days are flagged, then (after approval) their grants are
  snapshotted and the user is disabled. After a grace period all roles are revoked and the user is dropped.

```
 Engines ──poll──► Collectors ──metrics──► Rules + baselines ──► Incidents ──► Investigator (Claude, read-only)
    ▲                                                                │                 │ RCA + proposals
    │ approved action                                                ▼                 ▼
    └────── Executor (allowlist, executor creds, audit) ◄── approve ── Dashboard / Slack / Teams / PagerDuty / email
```

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -e ".[all,dev]"
copy .env.example .env          # fill in ANTHROPIC_API_KEY, MONITOR_USERS, webhooks, Snowflake keys
.\.venv\Scripts\pytest -q       # 65 tests; no databases or API key needed

# local fault lab (Docker Desktop must be running). Lab ports are 55432 / 33306 / 14330 so they never
# collide with databases already installed on the default ports.
docker compose -f lab/docker-compose.yml up -d
.\.venv\Scripts\python lab\setup_mssql.py

.\.venv\Scripts\monitor check                     # connectivity to every enabled target
.\.venv\Scripts\monitor serve                     # collectors + dashboard on http://127.0.0.1:8080
```

### Watch the agent work end to end
```powershell
.\.venv\Scripts\python lab\faults.py pg-blocking  # holds a row lock with 3 waiters for 10 minutes
# within ~2 minutes: incident "Session blocked for more than 60s" opens, Slack/Teams/PagerDuty notified,
# the agent investigates and proposes kill_session on the blocker -> approve it in the dashboard.
```
Other scenarios: `pg-idle-in-txn`, `pg-long-query`, `mysql-blocking`, `mssql-blocking`.

## CLI

| Command | What it does |
|---|---|
| `monitor check` | Health of each enabled target |
| `monitor collect-once [--target X] [--wait]` | One collection + rule evaluation (optionally wait for RCAs) |
| `monitor serve [--port 8080] [--no-collect]` | Scheduler + REST API + dashboard |
| `monitor run` | Scheduler only (no API) |
| `monitor investigate <incident_id>` | Run or re-run the AI investigation |
| `monitor ask "why is lab-postgres slow?"` | Ad-hoc question to the agent (read-only tools) |
| `monitor actions list / approve <id> / reject <id>` | Approval queue from the terminal |
| `monitor governance scan / run / approve <case> / keep <case> / restore <case>` | Snowflake user cleanup |

## Configuration

| File | Purpose |
|---|---|
| `config/settings.yaml` | Intervals, LLM model/effort/budget, notification routing by severity |
| `config/targets.yaml` | Targets, each with a **monitor** (read-only) and an **executor** credential set |
| `config/targets_ui.yaml` | Servers added from the dashboard (**Targets → Add server**). Their passwords are written to `.env` |
| `config/rules/*.yaml` | Detection rules (threshold or 7-day-baseline anomaly) |
| `config/governance.yaml` | Snowflake inactive-user policy |
| `runbooks/*.md` | Team knowledge the agent searches during investigations |

Secrets come from environment variables / `.env` (`${VAR}` expansion in YAML). Snowflake uses key-pair auth.

## What is monitored

| Engine | Signals |
|---|---|
| PostgreSQL | connections vs max, active sessions, blocking (`pg_blocking_pids`), longest query, idle-in-transaction, replication lag, deadlocks, dead-tuple bloat, `pg_stat_statements` |
| MySQL | threads, blocking (`sys.innodb_lock_waits`), longest query/transaction, replica lag (NULL = stopped), deadlocks, digest stats, waits |
| SQL Server | sessions, blocking chain, longest request, deadlocks (+ `system_health` XE graphs), AG lag, Agent job failures, tempdb free space, missing indexes, wait stats, cached plans |
| Snowflake | **Every minute, free (`SHOW` only):** running/queued queries per warehouse, lock waits. **Config audit, free:** auto-suspend, auto-resume, statement timeout, resource monitors (quota and suspend), multi-cluster at max. **Every 30 min (one short warehouse burst):** long-running/failed/blocked queries, credits/hour (anomaly), local and remote spill per warehouse, task failures, failed logins. **Every 6 h:** warehouse cache reuse, partition pruning, idle credits, cloud-services ratio. Approvable fix: `set_warehouse_parameter` (bounded) |

## Security model

1. **Read-only database roles** for collectors and the agent (`pg_monitor`; MySQL `PROCESS` + `performance_schema`/`sys`;
   MSSQL `VIEW SERVER STATE`; Snowflake `MONITOR_ROLE`, see `docs/snowflake_setup.sql`). Sessions are also forced
   read-only where the engine supports it.
2. **SQL guard** (`agent/sql_guard.py`). The agent's own SQL is parsed with sqlglot. Only a single SELECT/SHOW
   against **system views** is allowed. Business tables, DML/DDL, `SELECT INTO`, `FOR UPDATE`, and dangerous
   functions (`pg_terminate_backend`, `query_to_xml`, `OPENROWSET`, `RESULT_SCAN`, `SYSTEM$CANCEL_QUERY`, ...) are
   rejected.
3. **Redaction.** Literal values in query text are replaced with `?` before anything reaches the LLM.
4. **Action allowlist** (`actions/allowlist.py`). The agent proposes `{type, params}`, never SQL. Statements are
   rendered from validated parameters. Kinds: `kill_session`, `cancel_query`, `resize_warehouse` (capped by
   `limits.max_warehouse_size`), `suspend_warehouse`, `analyze_table`, `create_index_script` (script only, never run).
5. **Approval + audit.** Execution requires an `approver` token. Every proposal, approval, tool call and result
   goes to the append-only `audit_log` table.
6. **Prompt-injection hygiene.** Tool output is treated as data; the system prompt says so explicitly, and the
   tools give the agent no way to make changes.

## Snowflake inactive-user cleanup

Daily (configurable) job, `dry_run: true` by default:

1. **Detect.** `ACCOUNT_USAGE.USERS` where the last successful login (or the creation date, if the user never
   logged in) is more than 90 days ago. A live `SHOW USERS` re-check runs before any change.
2. **Exclude.** Service users, allowlisted users, the monitor/executor users, holders of protected roles
   (resolved through the role hierarchy), users carrying the keep tag, and users with any query activity in the
   window are all skipped.
3. **Safety stop.** If more than `max_flagged_pct` of all users would be flagged, nothing happens and you get
   an alert.
4. **Approve** in the dashboard. Grants (`SHOW GRANTS TO USER`) and properties (`DESCRIBE USER`) are snapshotted
   to the database **before** `ALTER USER ... SET DISABLED = TRUE`.
5. **Grace period** (14 days). If someone re-enables the user, the case is cancelled.
6. **Revoke** every role except PUBLIC, unset RSA keys, `DROP USER`. Roles that are left with no grantees are
   reported as orphaned. They are never auto-dropped.
7. **Restore.** Before the drop: re-enable and re-grant. After the drop: re-create the user from the snapshot and
   re-grant its roles. The password or keys must be re-issued.

At most `max_users_per_run` disable/drop operations run per job.

## Project layout
```
src/monitor/
  adapters/      base interface + postgres, mysql, mssql, snowflake
  detector/      rules, baselines, incident correlation
  agent/         investigator loop, tools, sql_guard, redaction, prompts, RCA schema
  actions/       allowlist + approval executor
  governance/    Snowflake inactive-user lifecycle
  notify/        Slack, Teams, PagerDuty, email routing
  api/           FastAPI + dashboard (static/index.html)
  collector/     APScheduler jobs
lab/             docker-compose, monitor-role init scripts, fault injection
tests/           unit + end-to-end tests with fake adapters and a fake Claude client
```

## Not built yet (next steps)
- Slack/Teams **interactive** approve buttons. Messages currently link to the dashboard, where approval happens.
- A `get_recent_changes` tool (DDL history / deploy webhooks) for "what changed?" correlation.
- A replay-based eval set for RCA quality (record incident snapshots, score root cause and fix).
- Production deployment: Postgres/Timescale state store (set `MONITOR_DB_URL`), container image, SSO for the
  dashboard in place of bearer tokens.
