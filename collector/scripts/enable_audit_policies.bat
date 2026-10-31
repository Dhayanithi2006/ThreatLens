@echo off
:: ThreatLens Windows Security Audit Policy Configuration Script
:: Run this script as Administrator to configure auditing for required security event IDs.
::
:: Event IDs activated:
::   4624 - Successful Logon
::   4625 - Failed Logon
::   4648 - Logon using explicit credentials (RunAs)
::   4672 - Special privileges assigned to new logon
::   4688 - Process creation (with command line arguments enabled)
::   4698 - Scheduled task created
::   4720 - User account created
::   5140 - Network share object accessed
::   5156 - Windows Filtering Platform: Allowed connection
::   5157 - Windows Filtering Platform: Blocked connection

setlocal enabledelayedexpansion

echo.
echo =====================================================================
echo  ThreatLens Endpoint Security Audit Policy Configuration
echo =====================================================================
echo.

:: 1. Verify Administrative Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo         Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

echo The following Windows advanced audit policies will be enabled:
echo   - Logon / Logoff:
echo       * Subcategory "Logon" (Success + Failure: Events 4624, 4625)
echo       * Subcategory "Special Logon" (Success: Event 4672)
echo       * Subcategory "Other Logon/Logoff Events" (Success: Event 4648)
echo   - Detailed Tracking:
echo       * Subcategory "Process Creation" (Success: Event 4688)
echo       * Registry Key: ProcessCreationIncludeCmdLine_Enabled = 1
echo   - Account Management:
echo       * Subcategory "User Account Management" (Success + Failure: Event 4720)
echo   - Object Access:
echo       * Subcategory "File Share" (Success + Failure: Event 5140)
echo       * Subcategory "Other Object Access Events" (Success: Event 4698)
echo   - Policy Change / Filtering Platform:
echo       * Subcategory "Filtering Platform Connection" (Success + Failure: Events 5156, 5157)
echo.
echo NOTE: ThreatLens Collector automatically sanitizes passwords from command lines.
echo.

set /p CONFIRM="Do you want to apply these audit policy changes? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo [INFO] Operation cancelled by administrator. No changes were made.
    pause
    exit /b 0
)

echo.
echo [1/5] Backing up Current Windows Security Audit Policies...
set BACKUP_FILE=%~dp0audit_policy_backup.csv
set REG_BACKUP=%~dp0process_creation_cmdline_backup.txt

auditpol /backup /file:"%BACKUP_FILE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Current audit policies backed up to: %BACKUP_FILE%
) else (
    echo [WARNING] Could not create auditpol CSV backup; proceeding with caution.
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled > "%REG_BACKUP%" 2>&1
echo [OK] Process creation command-line registry state backed up to: %REG_BACKUP%

echo.
echo [2/5] Configuring Advanced Audit Subcategories via auditpol...

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:disable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

echo.
echo [3/5] Enabling Command Line Auditing in Process Creation (Event 4688)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
if %errorLevel% equ 0 (
    echo [OK] ProcessCreationIncludeCmdLine_Enabled set to 1.
) else (
    echo [WARNING] Could not set registry key for command-line auditing.
)

echo.
echo [4/5] Recommended Security Log Buffer Configuration...
echo Setting Security log maximum size to 512MB to prevent event truncation:
wevtutil sl Security /ms:536870912 /ab:true
if %errorLevel% equ 0 (
    echo [OK] Security log buffer expanded to 512MB (circular rollover).
) else (
    echo [WARNING] Could not resize Security event log.
)

echo.
echo [5/5] Verifying Configured Audit Policies...
echo ---------------------------------------------------------------------
auditpol /get /subcategory:"Logon","Process Creation","File Share","Filtering Platform Connection"
echo ---------------------------------------------------------------------

echo.
echo [SUCCESS] Windows Security Audit policies configured for ThreatLens.
echo           To restore the exact previous policy state, run scripts\revert_audit_policies.bat.
echo.
pause

