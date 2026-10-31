@echo off
:: ThreatLens Collector - Windows Installation Script
:: Run this as Administrator on the endpoint you want to monitor.
::
:: This script:
::   1. Creates the installation directory
::   2. Copies the collector agent and config template
::   3. Registers a Windows Scheduled Task to run the collector
::   4. Does NOT change audit policy (see INSTALL.md for manual audit policy steps)
::   5. Does NOT start the task automatically (admin must verify config first)

setlocal enabledelayedexpansion

set INSTALL_DIR=C:\ThreatLensCollector
set AGENT_SRC=%~dp0threatlens_collector.py
set CONFIG_TEMPLATE=%~dp0config.template.json
set TASK_NAME=ThreatLensCollector

echo.
echo ===================================================
echo  ThreatLens Collector Installation
echo ===================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

:: Check Python availability
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python 3 is not in PATH. Please install Python 3.8+ first.
    echo         Download from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Verify Python version
python -c "import sys; assert sys.version_info >= (3,8), 'Python 3.8+ required'" >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python 3.8 or later is required.
    pause
    exit /b 1
)

echo [1/5] Creating installation directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to create directory %INSTALL_DIR%
        pause
        exit /b 1
    )
)

echo [2/5] Copying collector agent...
copy /Y "%AGENT_SRC%" "%INSTALL_DIR%\threatlens_collector.py" >nul
if %errorLevel% neq 0 (
    echo [ERROR] Failed to copy agent script.
    pause
    exit /b 1
)

echo [3/5] Copying configuration template...
if not exist "%INSTALL_DIR%\config.json" (
    copy /Y "%CONFIG_TEMPLATE%" "%INSTALL_DIR%\config.json" >nul
    echo.
    echo [!] IMPORTANT: Edit %INSTALL_DIR%\config.json before starting the collector.
    echo     Set: server_url, collector_id, and token
    echo.
) else (
    echo     Existing config.json preserved (not overwritten).
)

echo [4/5] Registering Scheduled Task: %TASK_NAME%
:: Remove existing task if present
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
)

:: Create task to run every 1 minute, on system startup, as SYSTEM
:: The task will NOT run until config.json is properly configured.
schtasks /create ^
  /tn "%TASK_NAME%" ^
  /sc MINUTE /mo 1 ^
  /tr "python \"%INSTALL_DIR%\threatlens_collector.py\" --config \"%INSTALL_DIR%\config.json\" --run-once" ^
  /ru SYSTEM ^
  /f >nul
if %errorLevel% neq 0 (
    echo [WARNING] Failed to register scheduled task. You can run the collector manually:
    echo   python %INSTALL_DIR%\threatlens_collector.py --config %INSTALL_DIR%\config.json
) else (
    echo     Scheduled task registered (NOT yet started — configure config.json first).
)

echo [5/5] Setting restrictive permissions on installation directory...
icacls "%INSTALL_DIR%" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" >nul 2>&1
icacls "%INSTALL_DIR%\config.json" /inheritance:r /grant:r "SYSTEM:R" /grant:r "Administrators:F" >nul 2>&1

echo.
echo ===================================================
echo  Installation complete.
echo ===================================================
echo.
echo  NEXT STEPS:
echo  1. Edit config.json:    %INSTALL_DIR%\config.json
echo     - Set server_url, collector_id, token
echo  2. (Optional) Enable extended audit policy (see INSTALL.md for exact gpmc steps)
echo  3. Test connectivity:   python %INSTALL_DIR%\threatlens_collector.py --run-once
echo  4. Enable the task:     schtasks /run /tn %TASK_NAME%
echo.
echo  To uninstall, run: %~dp0uninstall.bat
echo.
pause
endlocal

