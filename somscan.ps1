<#
.SYNOPSIS
    SOM-SCAN launcher for Windows Terminal / PowerShell.
.DESCRIPTION
    First run / a broken environment starts the guided setup, then runs the CLI.
    Use `somscan gui` to start the web console in the background.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $ScriptDir ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"

function Find-SystemPython {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { return @("py.exe", "-3") }
    $candidates = @()
    $candidates += (Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $candidates += (Get-ChildItem -Path "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    foreach ($c in $candidates) { if (Test-Path $c) { return @($c) } }
    if (Get-Command python.exe -ErrorAction SilentlyContinue) { return @("python.exe") }
    return $null
}

function Test-Core($python) {
    if (-not (Test-Path $python)) { return $false }
    & $python -c "import rich, textual, openai, httpx, dotenv, requests" 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

if (-not (Test-Core $Py)) {
    Write-Host "[somscan] environment incomplete - starting guided setup..."
    $sys = Find-SystemPython
    if (-not $sys) {
        Write-Error "Python 3.10+ was not found. Install it from https://python.org"
        exit 1
    }
    $setupArgs = @()
    if ($sys.Count -gt 1) { $setupArgs = $sys[1..($sys.Count - 1)] }
    $extra = @("--auto")
    if ($env:SOMSCAN_SKIP_TOOLKITS -eq "1") { $extra += "--no-toolkits" }
    & $sys[0] @setupArgs (Join-Path $ScriptDir "somscan.py") setup @extra
    if ($LASTEXITCODE -ne 0 -or -not (Test-Core $Py)) {
        Write-Error "Setup failed. Run: somscan setup"
        exit 1
    }
}

& $Py (Join-Path $ScriptDir "somscan.py") @args
exit $LASTEXITCODE
