-- Read-only monitoring user: process list, replication status and performance_schema/sys only.
CREATE USER 'monitor'@'%' IDENTIFIED BY 'monitor_pw';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'monitor'@'%';
GRANT SELECT ON performance_schema.* TO 'monitor'@'%';
GRANT SELECT, EXECUTE ON sys.* TO 'monitor'@'%';

USE labdb;
SET SESSION cte_max_recursion_depth = 10000;
CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, status VARCHAR(20), amount DECIMAL(12,2)) ENGINE=InnoDB;
INSERT INTO orders (id, customer_id, status, amount)
WITH RECURSIVE seq (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 5000)
SELECT n, n % 100, 'new', n * 1.5 FROM seq;
