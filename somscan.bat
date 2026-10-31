@echo off
rem SOM-SCAN launcher for Windows (PowerShell, cmd, Windows Terminal).
rem First run / broken environment starts the guided setup, then runs the CLI.
setlocal EnableExtensions

set "DIR=%~dp0"
set "VENV=%DIR%.venv"
set "PY=%VENV%\Scripts\python.exe"

rem Locate system Python for the setup script.
set "SYS="
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 set "SYS=py -3"
if not defined SYS (
    where python.exe >nul 2>&1
    if %ERRORLEVEL% EQU 0 set "SYS=python.exe"
)
if not defined SYS (
    echo [somscan] Python 3.10+ was not found. Install it from https://python.org
    exit /b 1
)

set "SETUP_ARGS=--auto"
if /I "%SOMSCAN_SKIP_TOOLKITS%"=="1" set "SETUP_ARGS=--auto --no-toolkits"

if not exist "%PY%" goto setup
"%PY%" -c "import rich, textual, openai, httpx, dotenv, requests" >nul 2>&1
if errorlevel 1 goto setup
goto run

:setup
echo [somscan] environment incomplete - starting guided setup...
%SYS% "%DIR%somscan.py" setup %SETUP_ARGS%
if errorlevel 1 (
    echo [somscan] setup failed. Run: somscan setup
    exit /b 1
)
if not exist "%PY%" (
    echo [somscan] no usable environment. Run: somscan setup
    exit /b 1
)
"%PY%" -c "import rich, textual, openai, httpx, dotenv, requests" >nul 2>&1
if errorlevel 1 (
    echo [somscan] environment is still incomplete. Run: somscan setup
    exit /b 1
)

:run
"%PY%" "%DIR%somscan.py" %*
exit /b %ERRORLEVEL%
