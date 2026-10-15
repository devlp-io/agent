@echo off
rem SOM-SCAN CLI launcher for Windows Terminal & Command Prompt

setlocal

rem 1. Check user AppData Python installation
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%~dp0somscan.py" %*
    exit /b %ERRORLEVEL%
)

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" (
        "%%D\python.exe" "%~dp0somscan.py" %*
        exit /b %ERRORLEVEL%
    )
)

rem 2. Check py launcher
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py.exe "%~dp0somscan.py" %*
    exit /b %ERRORLEVEL%
)

rem 3. Check Program Files Python
for /d %%D in ("%ProgramFiles%\Python3*") do (
    if exist "%%D\python.exe" (
        "%%D\python.exe" "%~dp0somscan.py" %*
        exit /b %ERRORLEVEL%
    )
)

rem 4. Check system python (skip WindowsApps stub if not installed)
python.exe -c "import sys" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python.exe "%~dp0somscan.py" %*
    exit /b %ERRORLEVEL%
)

echo [SOM-SCAN Error] Python 3.10+ executable was not found.
echo Please verify Python is installed or run with Python directly:
echo   %%LOCALAPPDATA%%\Programs\Python\Python312\python.exe somscan.py
exit /b 1
