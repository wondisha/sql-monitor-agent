@echo off
REM Starts the lab databases (if Docker Desktop is running), then the monitor + dashboard.
REM Close this window (or press Ctrl+C) to stop the dashboard.
cd /d "%~dp0"

docker info >nul 2>&1
if errorlevel 1 (
  echo [!] Docker Desktop is not running - the lab databases will show as unreachable.
  echo     Start Docker Desktop, wait until it says "Engine running", then run this file again.
  echo.
) else (
  echo Starting lab databases...
  docker compose -f lab\docker-compose.yml up -d
)

for /f "tokens=3 delims=:" %%t in ('findstr /b "MONITOR_USERS=" .env') do set TOKEN=%%t
echo.
echo Dashboard: http://127.0.0.1:8080
echo Login token: %TOKEN%
echo.
start "" http://127.0.0.1:8080
.venv\Scripts\monitor.exe serve --port 8080
pause
