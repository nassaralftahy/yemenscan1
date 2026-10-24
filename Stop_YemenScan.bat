@echo off
title YemenScan Platform - Stop
chcp 65001 >nul
echo ========================================================
echo          Stopping YemenScan Platform and Database
echo ========================================================
echo.

cd /d "%~dp0"

:: 1. Terminate FastAPI backend server on port 8000
echo [*] [1/2] Stopping FastAPI Web Server on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)

:: 2. Stop Docker Containers cleanly
echo [*] [2/2] Stopping PostgreSQL container in Docker...
docker compose down

echo.
echo ========================================================
echo  [+] All YemenScan services have been stopped cleanly!
echo ========================================================
ping 127.0.0.1 -n 3 >nul
