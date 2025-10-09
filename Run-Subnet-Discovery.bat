@echo off
REM Batch file to run Subnet-Discovery.ps1 with bypass execution policy
REM Run this batch file as Administrator for best results

echo ================================================
echo Subnet Discovery Script Launcher
echo ================================================
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Define the PowerShell script path
set "PS_SCRIPT=%SCRIPT_DIR%Subnet-Discovery.ps1"

REM Check if the PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo ERROR: PowerShell script not found at: %PS_SCRIPT%
    echo.
    echo Please ensure Subnet-Discovery.ps1 is in the same directory as this batch file.
    pause
    exit /b 1
)

echo Running PowerShell script: %PS_SCRIPT%
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

REM Run the PowerShell script with bypass execution policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*

echo.
echo Script execution completed.
echo Press any key to exit...
pause >nul
