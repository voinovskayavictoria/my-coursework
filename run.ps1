
param(
    [int]$Port = 8000,
    [switch]$Install
)

# Функция: получить PID процесса, который слушает указанный порт
function Get-PidForPort([int]$port) {
    $lines = netstat -aon | findstr ":$port"
    if (-not $lines) { return $null }
    foreach ($ln in $lines) {
        $parts = $ln -split '\s+' | Where-Object { $_ -ne '' }
        $pid = $parts[-1]
        if ($pid -match '^[0-9]+$') { return [int]$pid }
    }
    return $null
}

Write-Host "[run.ps1] Starting helper (port=$Port)" -ForegroundColor Cyan

$targetPid = Get-PidForPort -port $Port
if ($targetPid) {
    Write-Host "[run.ps1] Port $Port is in use by PID $targetPid -- attempting to terminate..." -ForegroundColor Yellow
    try {
        taskkill /PID $targetPid /F | Out-Null
        Start-Sleep -Milliseconds 300
        Write-Host "[run.ps1] Process $targetPid terminated." -ForegroundColor Green
    }
    catch {
        Write-Host "[run.ps1] Failed to terminate PID ${targetPid}: $_" -ForegroundColor Red
        Write-Host "Stop the running server manually and re-run this script." -ForegroundColor Yellow
        exit 1
    }
}

# Активация виртуального окружения, если оно существует
$venvActivate = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"
$pythonExe = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvActivate) {
    Write-Host "[run.ps1] Activating venv..." -ForegroundColor Cyan
    & $venvActivate
} else {
    Write-Host "[run.ps1] Warning: venv Activate.ps1 not found at $venvActivate" -ForegroundColor Yellow
}

# Установка зависимостей, если указан флаг -Install
if ($Install) {
    $req = Join-Path $PSScriptRoot "requirements.txt"
    if (Test-Path $req) {
        Write-Host "[run.ps1] Installing requirements..." -ForegroundColor Cyan
        & $pythonExe -m pip install -r $req
    } else {
        Write-Host "[run.ps1] requirements.txt not found, skipping install." -ForegroundColor Yellow
    }
}

if (-not (Test-Path $pythonExe)) {
    Write-Host "[run.ps1] Python executable not found at $pythonExe. Ensure venv is created." -ForegroundColor Red
    exit 1
}

Write-Host "[run.ps1] Launching server using $pythonExe app.py" -ForegroundColor Cyan
& $pythonExe app.py
