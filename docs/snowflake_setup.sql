-- Snowflake roles for sql-monitor-agent. Run as SECURITYADMIN (or ACCOUNTADMIN where noted).
-- Two service users with key-pair auth:
--   MONITOR_SVC  -> MONITOR_ROLE  (read-only: collectors + AI agent)
--   GOV_SVC      -> GOV_EXECUTOR  (approved changes only: cancel queries, resize/suspend warehouses,
--                                  disable / revoke / drop inactive users)

USE ROLE SECURITYADMIN;

-- ---------- read-only monitoring ----------
CREATE ROLE IF NOT EXISTS MONITOR_ROLE;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE MONITOR_ROLE;   -- ACCOUNT_USAGE views (needs ACCOUNTADMIN)
GRANT MONITOR USAGE ON ACCOUNT TO ROLE MONITOR_ROLE;                    -- metering / load history
GRANT MONITOR EXECUTION ON ACCOUNT TO ROLE MONITOR_ROLE;                -- task history for all tasks
-- MONITOR on each warehouse lets INFORMATION_SCHEMA.QUERY_HISTORY show other users' queries on it:
-- GRANT MONITOR ON WAREHOUSE <each_warehouse> TO ROLE MONITOR_ROLE;

CREATE WAREHOUSE IF NOT EXISTS MONITOR_WH WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60 AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE;
GRANT USAGE ON WAREHOUSE MONITOR_WH TO ROLE MONITOR_ROLE;
CREATE DATABASE IF NOT EXISTS MONITOR_DB;                               -- empty; gives a context for INFORMATION_SCHEMA
GRANT USAGE ON DATABASE MONITOR_DB TO ROLE MONITOR_ROLE;

CREATE USER IF NOT EXISTS MONITOR_SVC TYPE = SERVICE DEFAULT_ROLE = MONITOR_ROLE DEFAULT_WAREHOUSE = MONITOR_WH
  RSA_PUBLIC_KEY = '<paste public key>';
GRANT ROLE MONITOR_ROLE TO USER MONITOR_SVC;

-- ---------- executor (used only after human approval) ----------
CREATE ROLE IF NOT EXISTS GOV_EXECUTOR;
GRANT ROLE MONITOR_ROLE TO ROLE GOV_EXECUTOR;          -- reads for previews and snapshots
GRANT MANAGE GRANTS ON ACCOUNT TO ROLE GOV_EXECUTOR;   -- SHOW GRANTS / REVOKE ROLE from users
GRANT ROLE USERADMIN TO ROLE GOV_EXECUTOR;             -- ALTER / DROP USER on users owned by USERADMIN
-- Per warehouse the agent may resize, suspend or cancel queries on:
-- GRANT MODIFY, OPERATE ON WAREHOUSE <warehouse> TO ROLE GOV_EXECUTOR;

CREATE USER IF NOT EXISTS GOV_SVC TYPE = SERVICE DEFAULT_ROLE = GOV_EXECUTOR DEFAULT_WAREHOUSE = MONITOR_WH
  RSA_PUBLIC_KEY = '<paste public key>';
GRANT ROLE GOV_EXECUTOR TO USER GOV_SVC;

-- Optional "keep" tag for users that must never be cleaned up:
-- CREATE TAG IF NOT EXISTS MONITOR_DB.PUBLIC.KEEP_USER;
-- ALTER USER <name> SET TAG MONITOR_DB.PUBLIC.KEEP_USER = 'true';
-- and set keep_tag: MONITOR_DB.PUBLIC.KEEP_USER in config/governance.yaml
