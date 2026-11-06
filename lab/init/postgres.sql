-- Read-only monitoring role: pg_monitor gives pg_stat_* visibility for all sessions, no data access.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE ROLE monitor LOGIN PASSWORD 'monitor_pw';
GRANT pg_monitor TO monitor;
ALTER ROLE monitor SET default_transaction_read_only = on;

-- Sample business table used by the fault scripts (monitor has NO access to it).
CREATE TABLE orders (id int PRIMARY KEY, customer_id int, status text, amount numeric);
INSERT INTO orders SELECT g, g % 1000, 'new', g * 1.5 FROM generate_series(1, 200000) g;
REVOKE ALL ON orders FROM PUBLIC;
