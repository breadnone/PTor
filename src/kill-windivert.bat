@echo off
title Force Kill WinDivert
echo Searching for WinDivert-related processes...
echo.

set found=0

for /f "tokens=1,2" %%a in ('tasklist /fo table /nh ^| findstr /I "divert"') do (
    echo Killing process: %%a  PID: %%b
    taskkill /F /PID %%b >nul 2>&1
    set found=1
)

if %found%==0 (
    echo No WinDivert-related processes found running.
) else (
    echo.
    echo Done. All matching processes force-killed.
)

echo.
echo Attempting to stop/remove WinDivert driver if present...
sc query WinDivert >nul 2>&1
if %errorlevel%==0 (
    sc stop WinDivert >nul 2>&1
    sc delete WinDivert >nul 2>&1
    echo WinDivert driver stopped and removed.
) else (
    echo WinDivert driver service not found.
)

echo.
echo All done.
pause