@echo off
set script_dir="%~dp0"
echo Building and running Echelon X Encryption UI...
cd %script_dir%EncryptionUI

dotnet build > build_log.txt 2>&1
if %errorlevel% neq 0 (
    echo Build failed. Check build_log.txt for details.
    pause
    exit /b %errorlevel%
)

dotnet run > run_log.txt 2>&1
if %errorlevel% neq 0 (
    echo Application failed to run. Check run_log.txt for details.
    pause
    exit /b %errorlevel%
)

echo Application is running...
pause
