@echo off
rem SOM-SCAN one-time installer for cmd / Windows Terminal.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 exit /b 1
echo.
echo Done. Open a new terminal and run: somscan
