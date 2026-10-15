<#
.SYNOPSIS
    SOM-SCAN CLI launcher for Windows Terminal / PowerShell
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Look for Python 3.12 or any Python 3.x in user AppData
$pythonCandidates = @(
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe"
) + (Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

$pyExe = $pythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $pyExe) {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        $pyExe = "py.exe"
    } elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
        # Verify it is not the WindowsApps dummy stub
        $test = & python.exe -c "import sys; print(sys.version)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pyExe = "python.exe"
        }
    }
}

if (-not $pyExe) {
    Write-Error "Python 3.10+ was not found. Please install Python or specify its path."
    exit 1
}

& $pyExe "$ScriptDir\somscan.py" @args
