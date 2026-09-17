@echo off
rem PTor clear-startup. Removes the Windows logon startup entries so PTor no
rem longer launches on logon. Safe to run anytime: only the value/shortcut
rem NAME "PTor" goes (no other program registers itself under that name) and
rem everything else is left alone.
rem No admin needed for the per-user entries (HKCU Run + user Startup folder).
rem The machine-wide entries (HKLM Run + common Startup folder) are attempted
rem too and skipped silently without admin rights.
setlocal

echo --- HKCU Run "PTor" [per-user, written by Config -^> Windows startup] ---
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor >nul 2>nul
if errorlevel 1 (
  echo Absent - nothing to delete.
) else (
  for /f "tokens=2*" %%A in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor 2^>nul ^| findstr /i /c:"PTor"') do echo Was: %%B
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor /f >nul 2>nul
  if errorlevel 1 (
    echo FAILED to delete - is the registry locked by policy or a security tool?
  ) else (
    echo Deleted.
  )
)

echo.
echo --- HKLM Run "PTor" [machine-wide, only from old/manual setups] ---
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor >nul 2>nul
if errorlevel 1 (
  echo Absent - nothing to delete.
) else (
  reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor /f >nul 2>nul
  if errorlevel 1 (
    echo Present but could not delete - re-run this script as administrator.
  ) else (
    echo Deleted.
  )
)

echo.
echo --- Startup-folder shortcuts ---
set "USTART=%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\PTor.lnk"
if exist "%USTART%" (
  del /f /q "%USTART%" >nul 2>nul
  if exist "%USTART%" (
    echo User Startup PTor.lnk: FAILED to delete.
  ) else (
    echo User Startup PTor.lnk: deleted.
  )
) else (
  echo User Startup PTor.lnk: absent - nothing to delete.
)
set "CSTART=%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\PTor.lnk"
if exist "%CSTART%" (
  del /f /q "%CSTART%" >nul 2>nul
  if exist "%CSTART%" (
    echo Common Startup PTor.lnk: FAILED to delete - re-run as administrator.
  ) else (
    echo Common Startup PTor.lnk: deleted.
  )
) else (
  echo Common Startup PTor.lnk: absent - nothing to delete.
)

echo.
echo --- verify ---
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PTor >nul 2>nul
if errorlevel 1 (
  echo HKCU Run "PTor": gone.
) else (
  echo HKCU Run "PTor": STILL PRESENT - see message above.
)

echo.
echo All done. PTor will no longer start on Windows logon.
echo (In-app switch: Config -^> Windows startup. Uninstall.exe removes this too.)
pause
endlocal
exit /b 0
