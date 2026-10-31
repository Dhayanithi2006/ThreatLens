@echo off
:: ThreatLens Windows Security Audit Policy Rollback Script
:: Run this script as Administrator to restore Windows default auditing settings.

setlocal enabledelayedexpansion

echo.
echo =====================================================================
echo  ThreatLens Endpoint Security Audit Policy Rollback
echo =====================================================================
echo.

:: Verify Administrative Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo         Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

set /p CONFIRM="Are you sure you want to revert ThreatLens audit policies to their previous state? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo [INFO] Rollback cancelled.
    pause
    exit /b 0
)

set BACKUP_FILE=%~dp0audit_policy_backup.csv
set REG_BACKUP=%~dp0process_creation_cmdline_backup.txt

if exist "%BACKUP_FILE%" (
    echo.
    echo [1/3] Restoring exact audit policies from backup: %BACKUP_FILE%...
    auditpol /restore /file:"%BACKUP_FILE%"
    if %errorLevel% equ 0 (
        echo [OK] Exact original audit policies successfully restored.
    ) else (
        echo [WARNING] auditpol /restore returned non-zero; applying default baseline.
        goto apply_defaults
    )
) else (
    echo.
    echo [INFO] No prior backup file found at %BACKUP_FILE%. Reverting to standard baseline...
    goto apply_defaults
)

goto handle_registry

:apply_defaults
echo Disabling specialized audit subcategories...
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
auditpol /set /subcategory:"Special Logon" /success:disable /failure:disable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:disable /failure:disable
auditpol /set /subcategory:"File Share" /success:disable /failure:disable
auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:handle_registry
echo.
echo [2/3] Reverting ProcessCreationIncludeCmdLine_Enabled registry key...
if exist "%REG_BACKUP%" (
    findstr /i "0x1" "%REG_BACKUP%" >nul 2>&1
    if %errorLevel% equ 0 (
        echo [INFO] Original registry key was enabled; keeping enabled.
    ) else (
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f >nul 2>&1
        echo [OK] Registry value removed (restored to unconfigured).
    )
) else (
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f >nul 2>&1
    echo [OK] Registry value removed.
)

echo.
echo [3/3] Current Audit Policy Status:
echo ---------------------------------------------------------------------
auditpol /get /subcategory:"Logon","Process Creation","File Share","Filtering Platform Connection"
echo ---------------------------------------------------------------------

echo.
echo [SUCCESS] Windows Security Audit policies successfully reverted.
echo.
pause

