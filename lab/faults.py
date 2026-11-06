"""Inject known faults into the lab databases so you can watch detection -> RCA -> approval end to end.

Usage:  python lab/faults.py <scenario> [--seconds N]
Scenarios:
  pg-blocking       a transaction holds a row lock; other sessions queue behind it (expected: kill the blocker)
  pg-idle-in-txn    session opens a transaction and goes idle               (expected: idle_in_transaction)
  pg-long-query     a 20-minute query (pg_sleep)                            (expected: long_running_query)
  mysql-blocking    InnoDB row-lock wait                                    (expected: kill the blocker)
  mssql-blocking    open transaction blocking readers                       (expected: kill the blocker)
Each scenario runs until --seconds elapse (default 600) or Ctrl+C, then cleans up.
"""
from __future__ import annotations

import argparse
import threading
import time


def _hold(seconds: int, cleanup):
    try:
        print(f"Fault active for {seconds}s - run `monitor collect-once` or watch the dashboard. Ctrl+C to stop.")
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
        print("cleaned up")


def pg(autocommit=False):
    import psycopg
    return psycopg.connect("host=localhost port=55432 dbname=labdb user=postgres password=labpass", autocommit=autocommit)


def pg_blocking(seconds):
    blocker = pg()
    blocker.execute("UPDATE orders SET status = 'locked' WHERE id = 1")   # lock held, never committed
    waiters = []

    def wait():
        c = pg(autocommit=True)   # waiters behave like normal app requests: finish once the lock is released
        waiters.append(c)
        try:
            c.execute("UPDATE orders SET status = 'waiting' WHERE id = 1")
        except Exception:  # noqa: BLE001 - terminated when the blocker is killed or on cleanup
            pass

    for _ in range(3):
        threading.Thread(target=wait, daemon=True).start()
    _hold(seconds, lambda: [_close(c) for c in [blocker, *waiters]])


def pg_idle_in_txn(seconds):
    c = pg()
    c.execute("SELECT * FROM orders WHERE id = 2 FOR UPDATE")
    _hold(seconds, lambda: _close(c))


def pg_long_query(seconds):
    c = pg(autocommit=True)
    threading.Thread(target=lambda: _quiet(lambda: c.execute("SELECT pg_sleep(1200), count(*) FROM orders")),
                     daemon=True).start()
    _hold(seconds, lambda: _close(c))


def mysql_blocking(seconds):
    import pymysql
    def mk(autocommit=False):
        return pymysql.connect(host="127.0.0.1", port=33306, user="root", password="labpass", database="labdb",
                               autocommit=autocommit)
    blocker = mk()
    blocker.begin()
    blocker.cursor().execute("UPDATE orders SET status = 'locked' WHERE id = 1")
    waiters = []

    def wait():
        c = mk(autocommit=True)
        waiters.append(c)
        c.cursor().execute("SET SESSION innodb_lock_wait_timeout = 1000")
        _quiet(lambda: c.cursor().execute("UPDATE orders SET status = 'waiting' WHERE id = 1"))

    for _ in range(3):
        threading.Thread(target=wait, daemon=True).start()
    _hold(seconds, lambda: [_close(c) for c in [blocker, *waiters]])


def mssql_blocking(seconds):
    import pyodbc
    cs = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost,14330;DATABASE=labdb;UID=sa;PWD=Lab_pass1!;"
          "Encrypt=yes;TrustServerCertificate=yes")
    blocker = pyodbc.connect(cs, autocommit=False)
    blocker.cursor().execute("UPDATE dbo.orders SET status = 'locked' WHERE id = 1")
    waiters = []

    def wait():
        c = pyodbc.connect(cs, autocommit=True)
        waiters.append(c)
        _quiet(lambda: c.cursor().execute("SELECT * FROM dbo.orders WHERE id = 1").fetchall())

    for _ in range(3):
        threading.Thread(target=wait, daemon=True).start()
    _hold(seconds, lambda: [_close(c) for c in [blocker, *waiters]])


def _quiet(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        pass


def _close(c):
    _quiet(c.rollback)
    _quiet(c.close)


SCENARIOS = {"pg-blocking": pg_blocking, "pg-idle-in-txn": pg_idle_in_txn, "pg-long-query": pg_long_query,
             "mysql-blocking": mysql_blocking, "mssql-blocking": mssql_blocking}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=sorted(SCENARIOS))
    ap.add_argument("--seconds", type=int, default=600)
    a = ap.parse_args()
    SCENARIOS[a.scenario](a.seconds)
