Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "         Starting Attijari Stack                  " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Go to project root (where this script lives)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# Kill any existing process on port 8000 to avoid error 10048
$Port = 8000
try {
    $existing = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Listen" }
    if ($existing) {
        foreach ($conn in $existing) {
            Write-Host "[CLEANUP] Killing existing process on port $Port (PID $($conn.OwningProcess))..." -ForegroundColor Yellow
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 2
    }
} catch {
    # Ignore errors from Get-NetTCPConnection
}

# Activate venv and run from src/
Set-Location (Join-Path $ScriptDir "src")
$VenvActivate = Join-Path $ScriptDir ".venv\Scripts\Activate.ps1"

if (Test-Path $VenvActivate) {
    Write-Host "[INFO] Activating virtual environment..." -ForegroundColor Green
    & $VenvActivate
} else {
    Write-Host "[WARN] No .venv found -- using system Python" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[START] Dashboard + background IMAP polling" -ForegroundColor Green
Write-Host "[START] http://localhost:$Port" -ForegroundColor Green
Write-Host "[START] Press Ctrl+C to stop" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

python main.py --serve

# Keep window open on crash
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Exited with code $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to close"
}
