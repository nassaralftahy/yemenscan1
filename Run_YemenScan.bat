@echo off
title YemenScan Platform
chcp 65001 >nul
echo ========================================================
echo          YemenScan Security Platform - Start
echo ========================================================
echo.

:: Change directory to script location
cd /d "%~dp0"

:: Detect Python executable (venv or system python)
set PYTHON_CMD=python
if exist "%~dp0venv\Scripts\python.exe" (
    set PYTHON_CMD="%~dp0venv\Scripts\python.exe"
)

:: 1. Free Port 8000 if occupied by a stale instance
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)

:: 2. Start Docker Container for PostgreSQL
echo [*] [1/4] Starting PostgreSQL container in Docker...
docker compose up -d db
if %ERRORLEVEL% neq 0 (
    echo [!] Warning: Docker did not start or is not running.
    echo [!] The platform will automatically fallback to SQLite (yemenscan.db).
) else (
    ping 127.0.0.1 -n 3 >nul
)

:: 3. Initialize Database and Seed System Settings
echo [*] [2/4] Checking and initializing database schema...
%PYTHON_CMD% init_db.py

:: 4. Launch Web Dashboard in Default Browser
echo [*] [3/4] Launching YemenScan Dashboard in browser...
ping 127.0.0.1 -n 2 >nul
start http://127.0.0.1:8000

:: 5. Start FastAPI Backend Server via Uvicorn
echo [*] [4/4] Starting FastAPI backend on http://127.0.0.1:8000 ...
echo ========================================================
echo  Platform is LIVE! You can close this window to stop it.
echo ========================================================
%PYTHON_CMD% -m uvicorn main:app --host 127.0.0.1 --port 8000

echo.
echo [*] Web server stopped.
echo [*] To also stop the background database container, run Stop_YemenScan.bat
pause
