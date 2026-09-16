@echo off
rem PTor versioned release builder.
rem Always run from the PTor project folder (this script cds there itself).
rem
rem Usage:
rem   build-release.bat            patch bump from latest Release\vX.Y.Z  (1.2.0 -^> 1.2.1)
rem   build-release.bat minor      minor bump                             (1.2.0 -^> 1.3.0)
rem   build-release.bat major      major bump                             (1.2.0 -^> 2.0.0)
rem   build-release.bat 2.1.0      explicit version ("v" prefix optional)
rem
rem Refuses to overwrite an existing Release\vX.Y.Z folder.
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=patch"

where dotnet >nul 2>nul
if errorlevel 1 (
  echo ERROR: dotnet SDK not found on PATH.
  exit /b 1
)

rem --- find highest existing Release\vX.Y.Z ---
set "MAXMAJ=-1"
set "MAXMIN=0"
set "MAXPAT=0"
set "MAXNUM=-1"
for /d %%D in (Release\v*.*.*) do (
  set "v=%%~nxD"
  set "v=!v:~1!"
  for /f "tokens=1-3 delims=." %%a in ("!v!") do (
    echo(%%a %%b %%c| findstr /r "^[0-9][0-9]* [0-9][0-9]* [0-9][0-9]*$" >nul
    if not errorlevel 1 (
      set /a "num=(%%a*1000000)+(%%b*1000)+%%c"
      if !num! GTR !MAXNUM! (
        set "MAXNUM=!num!"
        set "MAXMAJ=%%a"
        set "MAXMIN=%%b"
        set "MAXPAT=%%c"
      )
    )
  )
)

rem --- resolve target version ---
set "NEWVER="
echo(%MODE%| findstr /r "^v*[0-9][0-9]*.[0-9][0-9]*.[0-9][0-9]*$" >nul
if not errorlevel 1 (
  for /f "tokens=1-3 delims=." %%a in ("%MODE%") do (
    set "a=%%a"
    set "a=!a:v=!"
    echo(!a! %%b %%c| findstr /r "^[0-9][0-9]* [0-9][0-9]* [0-9][0-9]*$" >nul
    if not errorlevel 1 set "NEWVER=!a!.%%b.%%c"
  )
  if "!NEWVER!"=="" (
    echo ERROR: could not parse version "%MODE%". Use X.Y.Z like 2.1.0.
    exit /b 1
  )
) else if /i "%MODE%"=="patch" (
  if !MAXMAJ!==-1 ( set "NEWVER=1.0.0" ) else ( set /a "MAXPAT+=1" & set "NEWVER=!MAXMAJ!.!MAXMIN!.!MAXPAT!" )
) else if /i "%MODE%"=="minor" (
  if !MAXMAJ!==-1 ( set "NEWVER=1.0.0" ) else ( set /a "MAXMIN+=1" & set "NEWVER=!MAXMAJ!.!MAXMIN!.0" )
) else if /i "%MODE%"=="major" (
  if !MAXMAJ!==-1 ( set "NEWVER=1.0.0" ) else ( set /a "MAXMAJ+=1" & set "NEWVER=!MAXMAJ!.0.0" )
) else (
  echo Usage: %~nx0 [patch ^| minor ^| major ^| X.Y.Z]
  exit /b 1
)

if exist "Release\v%NEWVER%\" (
  echo ERROR: Release\v%NEWVER% already exists. Pass another mode or explicit version.
  exit /b 1
)

echo Building PTor v%NEWVER% ...
dotnet publish PTor.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:Version=%NEWVER% -p:AssemblyVersion=%NEWVER%.0 -p:FileVersion=%NEWVER%.0 -p:InformationalVersion=%NEWVER% -o "Release\v%NEWVER%"
if errorlevel 1 (
  echo ERROR: publish failed.
  exit /b 1
)
if not exist "Release\v%NEWVER%\PTor.exe" (
  echo ERROR: publish finished but Release\v%NEWVER%\PTor.exe is missing.
  exit /b 1
)
echo Publishing Uninstall.exe (NativeAOT: tiny, no .NET runtime needed) ...
rem NOTE: PublishAot implies self-contained single-file; DebugSymbols=false
rem because native PDBs (~13MB) would eat the size win. Keep the version
rem props so Uninstall.exe stamps match PTor.exe.
dotnet publish Uninstall\PTor.Uninstall.csproj -c Release -r win-x64 -p:PublishAot=true -p:DebugType=none -p:DebugSymbols=false -p:Version=%NEWVER% -p:AssemblyVersion=%NEWVER%.0 -p:FileVersion=%NEWVER%.0 -p:InformationalVersion=%NEWVER% -o "Release\v%NEWVER%"
if errorlevel 1 (
  echo ERROR: Uninstall publish failed.
  exit /b 1
)
rem Belt-and-suspenders: never ship the ~13MB native PDB even if an
rem incremental build reused symbol-carrying intermediates.
del /q "Release\v%NEWVER%\Uninstall.pdb" 2>nul
if not exist "Release\v%NEWVER%\Uninstall.exe" (
  echo ERROR: publish finished but Release\v%NEWVER%\Uninstall.exe is missing.
  exit /b 1
)
if not exist "Release\v%NEWVER%\rescue-internet.bat" (
  echo ERROR: Release\v%NEWVER%\rescue-internet.bat is missing -- Content include broken?
  exit /b 1
)
if not exist "Release\v%NEWVER%\fix-internet-now.bat" (
  echo ERROR: Release\v%NEWVER%\fix-internet-now.bat is missing -- Content include broken?
  exit /b 1
)
if not exist "Release\v%NEWVER%\kill-windivert.bat" (
  echo ERROR: Release\v%NEWVER%\kill-windivert.bat is missing -- Content include broken?
  exit /b 1
)
if not exist "Release\v%NEWVER%\clear-startup.bat" (
  echo ERROR: Release\v%NEWVER%\clear-startup.bat is missing -- Content include broken?
  exit /b 1
)
if not exist "Release\v%NEWVER%\README.md" (
  echo ERROR: Release\v%NEWVER%\README.md is missing -- Content include broken?
  exit /b 1
)
for %%F in ("Release\v%NEWVER%\PTor.exe") do echo OK: Release\v%NEWVER%\PTor.exe (%%~zF bytes)
for %%F in ("Release\v%NEWVER%\Uninstall.exe") do echo OK: Release\v%NEWVER%\Uninstall.exe (%%~zF bytes)
endlocal
