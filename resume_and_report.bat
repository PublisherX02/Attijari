@echo off
setlocal
cd /d "%~dp0"

echo ==================================================
echo   Resuming Attijari + atomic-red-team batch
echo ==================================================
echo.

:: Determine venv python, matching start.bat's own fallback logic
set PYTHON_EXE=python
if exist ".venv\Scripts\python.exe" (
    set PYTHON_EXE=.venv\Scripts\python.exe
) else if exist "C:\Users\moham\Attijari\.venv\Scripts\python.exe" (
    set PYTHON_EXE=C:\Users\moham\Attijari\.venv\Scripts\python.exe
)

:: Is the app already up? If not, start the full stack (Vault/Memurai/
:: Ollama/worker/app) via the existing start.bat, in its own window so
:: this script doesn't block on main.py --serve running forever.
:: (curl's own "connection failed" convention is exit-code/output "000",
:: which itself starts with a digit -- a naive findstr digit-match would
:: misread "down" as "up"; a real TCP connection-state check avoids that.)
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
if errorlevel 1 (
    echo [INFO] App not running -- starting the full stack via start.bat...
    start "Attijari Stack" cmd /c start.bat
) else (
    echo [INFO] App already appears to be running.
)

echo.
echo [INFO] Handing off to the resume-and-report script...
echo         (this will wait for the app, re-enqueue any unfinished
echo          samples, wait for the batch to drain, then build the report
echo          and open it automatically -- this can take a while)
echo.

"%PYTHON_EXE%" scripts\resume_and_report.py

echo.
echo Press any key to close this window...
pause >nul
