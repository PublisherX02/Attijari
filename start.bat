@echo off
title ImaniIA Claims Dashboard
cd /d "%~dp0"

echo ==================================================
echo          Starting ImaniIA Claims Dashboard
echo ==================================================

:: Kill existing process on port 8000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000.*LISTENING"') do (
    echo [CLEANUP] Killing PID %%a on port 8000...
    taskkill /PID %%a /F >nul 2>&1
)

:: Activate venv
if exist ".venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo [WARN] No .venv found -- using system Python
)

cd src
echo.
echo [START] Dashboard + background IMAP polling
echo [START] http://localhost:8000
echo [START] Admin Audit Panel: http://localhost:8000/audit
echo [START] Press Ctrl+C to stop
echo ==================================================
echo.

python main.py --serve

if errorlevel 1 (
    echo.
    echo [ERROR] Server crashed. Check output above.
    pause
)
