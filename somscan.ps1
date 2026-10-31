<#
.SYNOPSIS
    SOM-SCAN launcher for Windows Terminal / PowerShell.
.DESCRIPTION
    First run creates .venv, installs requirements + core toolkits, then runs.
    Use `somscan gui` to start the web console in the background.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $ScriptDir ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"

function Find-Python {
    $candidates = @()
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { return @("py.exe", "-3") }
    $candidates += (Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $candidates += (Get-ChildItem -Path "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    foreach ($c in $candidates) {
        if (Test-Path $c) { return @($c) }
    }
    if (Get-Command python.exe -ErrorAction SilentlyContinue) { return @("python.exe") }
    return $null
}

if (-not (Test-Path $Py)) {
    Write-Host "[somscan] first run - setting up Python environment (one time)..."
    $boot = Find-Python
    if (-not $boot) {
        Write-Error "Python 3.10+ was not found. Install it from https://python.org"
        exit 1
    }
    $bootArgs = @()
    if ($boot.Count -gt 1) { $bootArgs = $boot[1..($boot.Count - 1)] }
    & $boot[0] @bootArgs -m venv $Venv
    if (-not (Test-Path $Py)) {
        Write-Error "Failed to create virtual environment at $Venv"
        exit 1
    }
    & $Py -m pip install --upgrade pip setuptools wheel
    & $Py -m pip install -r (Join-Path $ScriptDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { Write-Error "Dependency install failed."; exit 1 }
    if ($env:SOMSCAN_SKIP_TOOLKITS -ne "1" -and (Test-Path (Join-Path $ScriptDir "installer.py"))) {
        Write-Host "[somscan] installing core toolkits (first run, this can take a few minutes)..."
        & $Py (Join-Path $ScriptDir "installer.py") preinstall core
    }
    "done" | Out-File -FilePath (Join-Path $ScriptDir ".bootstrap_done") -Encoding ascii
}

& $Py (Join-Path $ScriptDir "somscan.py") @args
exit $LASTEXITCODE
