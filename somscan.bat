@echo off
rem SOM-SCAN launcher for Windows (PowerShell, cmd, Windows Terminal).
rem First run creates .venv, installs requirements and core toolkits, then runs.
setlocal EnableExtensions

set "DIR=%~dp0"
set "VENV=%DIR%.venv"
set "PY=%VENV%\Scripts\python.exe"

if exist "%PY%" goto run

echo [somscan] first run - setting up Python environment (one time)...
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 -m venv "%VENV%"
) else (
    where python.exe >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [somscan] Python 3.10+ was not found. Install it from https://python.org
        exit /b 1
    )
    python.exe -m venv "%VENV%"
)

if not exist "%PY%" (
    echo [somscan] failed to create virtual environment at %VENV%
    echo           Try: py -3 -m venv "%VENV%"
    exit /b 1
)

"%PY%" -m pip install --upgrade pip setuptools wheel
"%PY%" -m pip install -r "%DIR%requirements.txt"
if errorlevel 1 (
    echo [somscan] dependency install failed.
    exit /b 1
)

if /I "%SOMSCAN_SKIP_TOOLKITS%"=="1" goto mark
if exist "%DIR%installer.py" (
    echo [somscan] installing core toolkits (first run, this can take a few minutes)...
    "%PY%" "%DIR%installer.py" preinstall core
)

:mark
echo done> "%DIR%.bootstrap_done" 2>nul

:run
"%PY%" "%DIR%somscan.py" %*
exit /b %ERRORLEVEL%
