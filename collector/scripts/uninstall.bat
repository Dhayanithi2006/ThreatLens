@echo off
:: ThreatLens Collector - Uninstall Script
:: Run as Administrator to completely remove the collector from this endpoint.

setlocal

set INSTALL_DIR=C:\ThreatLensCollector
set TASK_NAME=ThreatLensCollector

echo.
echo ===================================================
echo  ThreatLens Collector Uninstall
echo ===================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

echo [1/3] Stopping and removing Scheduled Task...
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    schtasks /end /tn "%TASK_NAME%" >nul 2>&1
    schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
    echo     Task removed.
) else (
    echo     Task not found (already removed).
)

echo [2/3] Removing installation directory...
if exist "%INSTALL_DIR%" (
    :: Securely delete the config file (contains token)
    if exist "%INSTALL_DIR%\config.json" (
        :: Overwrite with zeros before deleting
        python -c "open(r'%INSTALL_DIR%\config.json','wb').write(b'\x00'*4096)" >nul 2>&1
        del /f /q "%INSTALL_DIR%\config.json" >nul 2>&1
    )
    rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
    echo     Installation directory removed.
) else (
    echo     Installation directory not found (already removed).
)

echo [3/3] Uninstall complete.
echo.
echo  NOTE: Windows audit policy changes are NOT reverted automatically.
echo        Review Group Policy settings if you changed them during installation.
echo.
pause
endlocal

