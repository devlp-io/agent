<#
.SYNOPSIS
    SOM-SCAN one-time installer for Windows (PowerShell).
.DESCRIPTION
    Creates the local environment, installs core toolkits, and puts `somscan`
    on the user PATH so it works from any directory (PowerShell, cmd, Terminal).
#>
param(
    [switch]$NoToolkits,
    [string]$Prefix = "$env:LOCALAPPDATA\Programs\somscan"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "========================================================"
Write-Host "  SOM-SCAN installer"
Write-Host "  repo: $ScriptDir"
Write-Host "========================================================"

# Trigger the bootstrap path in somscan.ps1 (venv + requirements + toolkits).
if ($NoToolkits) { $env:SOMSCAN_SKIP_TOOLKITS = "1" }
& (Join-Path $ScriptDir "somscan.ps1") --version | Out-Null
$Py = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    Write-Error "Setup did not create .venv. Re-run this installer."
    exit 1
}
& $Py -c "import rich, textual, openai, httpx, dotenv, requests" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Core environment is incomplete. Run: somscan setup"
    exit 1
}

$Bin = Join-Path $Prefix "bin"
New-Item -ItemType Directory -Force -Path $Bin | Out-Null

$Cmd = Join-Path $Bin "somscan.cmd"

@"
@echo off
call "$ScriptDir\somscan.bat" %*
"@ | Set-Content -Path $Cmd -Encoding ASCII

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$parts = @($UserPath -split ";" | Where-Object { $_ })
if ($parts -notcontains $Bin) {
    $newPath = (($parts + $Bin) -join ";")
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

Write-Host ""
Write-Host "[OK] installed: $Cmd"
Write-Host "     somscan            launch the CLI"
Write-Host "     somscan gui        start the web console in the background"
Write-Host "     somscan gui stop   stop the web console"
Write-Host ""
Write-Host "Open a NEW terminal (so PATH refreshes), then run: somscan"
