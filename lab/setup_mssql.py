"""Create the lab database and a read-only monitor login on the SQL Server container."""
import time

import pyodbc

SA = ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost,14330;UID=sa;PWD=Lab_pass1!;"
      "Encrypt=yes;TrustServerCertificate=yes")

STATEMENTS = [
    "IF DB_ID('labdb') IS NULL CREATE DATABASE labdb",
    "IF SUSER_ID('monitor') IS NULL CREATE LOGIN monitor WITH PASSWORD = 'Monitor_pw1!', CHECK_POLICY = OFF",
    "GRANT VIEW SERVER STATE TO monitor",
    "GRANT VIEW ANY DEFINITION TO monitor",
    "USE msdb; IF USER_ID('monitor') IS NULL CREATE USER monitor FOR LOGIN monitor; "
    "GRANT SELECT ON dbo.sysjobhistory TO monitor; GRANT SELECT ON dbo.sysjobs TO monitor; "
    "GRANT EXECUTE ON dbo.agent_datetime TO monitor",
    "USE labdb; IF USER_ID('monitor') IS NULL CREATE USER monitor FOR LOGIN monitor; "
    "GRANT VIEW DATABASE STATE TO monitor",
    "USE labdb; IF OBJECT_ID('dbo.orders') IS NULL BEGIN "
    "CREATE TABLE dbo.orders (id int PRIMARY KEY, customer_id int, status varchar(20), amount decimal(12,2)); "
    "INSERT INTO dbo.orders SELECT TOP 50000 ROW_NUMBER() OVER (ORDER BY (SELECT 1)), 1, 'new', 1.5 "
    "FROM sys.all_objects a CROSS JOIN sys.all_objects b; END",
]


def main():
    for attempt in range(30):
        try:
            conn = pyodbc.connect(SA, autocommit=True, timeout=5)
            break
        except pyodbc.Error:
            print("waiting for SQL Server...")
            time.sleep(5)
    else:
        raise SystemExit("SQL Server did not come up")
    cur = conn.cursor()
    for s in STATEMENTS:
        cur.execute(s)
    print("SQL Server lab ready (login monitor / Monitor_pw1!)")


if __name__ == "__main__":
    main()
