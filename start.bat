@echo off
title Attijari Pipeline
cd /d "%~dp0"

echo ==================================================
echo          Starting Attijari Pipeline
echo ==================================================

:: Kill existing process on port 8000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000.*LISTENING"') do (
    echo [CLEANUP] Killing PID %%a on port 8000...
    taskkill /PID %%a /F >nul 2>&1
)

:: Activate venv (this repo has no local .venv -- fall back to the shared
:: Attijari venv, which has every dependency this app needs, rather than
:: silently dropping to system Python and crashing on the first missing package)
set PYTHON_EXE=python
if exist ".venv\Scripts\activate.bat" (
    echo [INFO] Activating local virtual environment...
    call .venv\Scripts\activate.bat
) else if exist "C:\Users\moham\Attijari\.venv\Scripts\python.exe" (
    echo [INFO] No local .venv -- using the Attijari venv ^(has all dependencies^)
    set PYTHON_EXE=C:\Users\moham\Attijari\.venv\Scripts\python.exe
) else (
    echo [WARN] No .venv found anywhere -- using system Python, this WILL likely fail
)

cd src
echo.
echo [START] Dashboard + background SMTP polling
echo [START] http://localhost:8000
echo [START] Admin Audit Panel: http://localhost:8000/audit
echo [START] Press Ctrl+C to stop
echo ==================================================
echo.

"%PYTHON_EXE%" main.py --serve

if errorlevel 1 (
    echo.
    echo [ERROR] Server crashed. Check output above.
    pause
)
