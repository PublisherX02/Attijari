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

:: Ensure Redis (Memurai) is up -- backs the RQ pipeline queue, rate
:: limiting, TOTP replay cache, and the detonation-window lock. Normally an
:: auto-start Windows service, but checked/started defensively so a manually
:: stopped service doesn't silently break the whole pipeline.
sc query Memurai | findstr "RUNNING" >nul
if errorlevel 1 (
    echo [INFO] Starting Memurai ^(Redis^) service...
    net start Memurai >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Could not start Memurai automatically -- start it manually ^(may need an elevated prompt^), app may fail to start.
    ) else (
        echo [INFO] Memurai started.
    )
) else (
    echo [INFO] Memurai ^(Redis^) already running.
)
echo.

:: Ensure Ollama is up. Unlike Postgres/Memurai, Ollama is NOT a Windows
:: service -- it only auto-starts via a Startup-folder shortcut at user
:: login (Ollama.lnk launching the tray app), so it's not guaranteed to be
:: running (closed tray icon, non-interactive session, etc.). This matters
:: more than it looks: main.py's run_pipeline() checks Ollama reachability
:: FIRST and silently defers the entire run if it's down (comment there
:: cites a real incident -- "23 emails burned overnight this way" when
:: Ollama was down) -- so a missing Ollama reproduces the exact "no email
:: analysis" symptom this session was called in to fix, silently.
call :check_ollama
if "%OLLAMA_HTTP%"=="200" goto ollama_already_up

echo [INFO] Ollama not running -- starting it...
start "Ollama Serve" /min ollama serve

set OLLAMA_TRIES=0
:wait_for_ollama
:: ping-based ~1s sleep, not `timeout /t` -- Windows' native timeout.exe
:: unconditionally fails with "ERROR: Input redirection is not supported,
:: exiting the process immediately" whenever its stdin isn't a genuine
:: interactive console (confirmed live: reproduced via both a Bash-tool
:: cmd.exe invocation AND a PowerShell invocation), which silently killed
:: this whole wait loop. ping doesn't touch stdin at all.
ping -n 2 127.0.0.1 >nul
set /a OLLAMA_TRIES=%OLLAMA_TRIES%+1
call :check_ollama
if "%OLLAMA_HTTP%"=="200" goto ollama_up
if %OLLAMA_TRIES% GEQ 20 (
    echo [WARN] Ollama did not come up after 20s -- continuing anyway, LLM analysis will be deferred until it is.
    goto ollama_section_done
)
goto wait_for_ollama

:ollama_up
echo [INFO] Ollama is up.
goto ollama_section_done

:ollama_already_up
echo [INFO] Ollama already running.

:ollama_section_done
echo.

:: Ensure the local Vault dev-mode server is up. Dev mode is in-memory (no
:: persistence), so every restart wipes the AppRole this app authenticates
:: with -- app.py/database.py read secrets from Vault at import time, so a
:: dead/unbootstrapped Vault crashes startup before it can even fetch mail.
set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root

call :check_vault
if "%VAULT_HTTP%"=="200" goto vault_already_up

echo [INFO] Vault dev server not running -- starting it...
start "Vault Dev Server" /min vault server -dev -dev-root-token-id="root" -dev-listen-address="127.0.0.1:8200"

set VAULT_TRIES=0
:wait_for_vault
ping -n 2 127.0.0.1 >nul
set /a VAULT_TRIES=%VAULT_TRIES%+1
call :check_vault
if "%VAULT_HTTP%"=="200" goto vault_bootstrap
if %VAULT_TRIES% GEQ 20 (
    echo [WARN] Vault did not come up after 20s -- continuing anyway, app may fail to start.
    goto vault_section_done
)
goto wait_for_vault

:vault_bootstrap
echo [INFO] Vault is up -- bootstrapping AppRole and migrating secrets...
"%PYTHON_EXE%" scripts\vault_bootstrap.py --write-env
"%PYTHON_EXE%" scripts\migrate_env_to_vault.py
goto vault_section_done

:vault_already_up
echo [INFO] Vault dev server already running.

:vault_section_done
echo.

:: Start the RQ worker that actually processes the pipeline queue. Plain
:: `rq worker` does not work on Windows (default Worker needs os.fork(),
:: registry cleanup hardcodes a signal.SIGALRM-based timeout) -- both are
:: worked around in scripts\run_worker_windows.py. Without SOME worker
:: consuming "attijari-pipeline", fetched emails queue up in Redis forever
:: and are never analyzed, even though the app itself looks fine.
tasklist /FI "WINDOWTITLE eq Attijari RQ Worker" /NH 2>nul | findstr /I "python" >nul
if errorlevel 1 (
    echo [INFO] Starting RQ worker for the pipeline queue...
    start "Attijari RQ Worker" /min "%PYTHON_EXE%" scripts\run_worker_windows.py
) else (
    echo [INFO] RQ worker already running.
)
echo.

cd src
echo.
echo [START] Dashboard + background SMTP polling
echo [START] http://localhost:8000
echo [START] Admin Audit Panel: http://localhost:8000/audit
echo [START] Vault UI ^(dev-mode, token "root"^): http://localhost:8200/ui
echo [START] Press Ctrl+C to stop
echo ==================================================
echo.

"%PYTHON_EXE%" main.py --serve

if errorlevel 1 (
    echo.
    echo [ERROR] Server crashed. Check output above.
    pause
)

goto :eof

:check_vault
for /f %%c in ('curl -s -o nul -w "%%{http_code}" http://127.0.0.1:8200/v1/sys/health 2^>nul') do set VAULT_HTTP=%%c
exit /b

:check_ollama
for /f %%c in ('curl -s -o nul -w "%%{http_code}" http://127.0.0.1:11434/api/version 2^>nul') do set OLLAMA_HTTP=%%c
exit /b
