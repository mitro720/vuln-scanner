@echo off
REM Vulnerability Scanner - Windows Startup Script
REM This script starts all components in parallel

echo ========================================
echo   Vulnerability Scanner - Starting
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed!
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

echo [1/3] Starting Backend Server (Node.js)...
start "Backend Server" cmd /k "cd backend && npm run dev"
timeout /t 2 /nobreak >nul

echo [2/3] Starting Frontend (React + Vite)...
start "Frontend Server" cmd /k "cd frontend && npm run dev"
timeout /t 2 /nobreak >nul

echo [3/3] Starting Python Scanner Engine...
start "Scanner Engine" cmd /k "cd scanner-core && python api_bridge.py"
timeout /t 2 /nobreak >nul

echo.
echo ========================================
echo   All Services Started!
echo ========================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:5173
echo Scanner:  http://localhost:8000
echo.
echo Press any key to stop all services...
pause >nul

REM Kill all processes when user presses a key
taskkill /FI "WindowTitle eq Backend Server*" /T /F >nul 2>nul
taskkill /FI "WindowTitle eq Frontend Server*" /T /F >nul 2>nul
taskkill /FI "WindowTitle eq Scanner Engine*" /T /F >nul 2>nul

echo All services stopped.
pause
