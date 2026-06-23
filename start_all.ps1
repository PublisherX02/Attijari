Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "         Starting Attijari Stack                  " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Ensure we are in the script's directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# Check if virtual environment is active or exists, activate it if needed
if (Test-Path ".venv\Scripts\Activate.ps1") {
    Write-Host "[INFO] Using virtual environment..." -ForegroundColor Green
    $PythonCmd = ".venv\Scripts\python.exe"
} else {
    Write-Host "[INFO] No local .venv found, using system Python..." -ForegroundColor Yellow
    $PythonCmd = "python"
}

if (!(Get-Command $PythonCmd -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python is not installed or not in the PATH." -ForegroundColor Red
    exit 1
}

Write-Host "`n1. Starting Background Pipeline Daemon..." -ForegroundColor White
Start-Process $PythonCmd -ArgumentList "src\main.py", "--daemon" -WindowStyle Normal

Write-Host "2. Starting Dashboard API Server..." -ForegroundColor White
Start-Process $PythonCmd -ArgumentList "src\main.py", "--serve" -WindowStyle Normal

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "All services started! The daemon and API server" -ForegroundColor Green
Write-Host "are now running in separate console windows." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
