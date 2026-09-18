@echo off
rem PTor emergency network rescue. Restores proxy, environment variables and
rem DNS resolvers left behind by a crashed or killed PTor, flushes the DNS
rem cache, clears stale checkpoints and removes PTor's own leftover WinDivert
rem service. Safe to run anytime: proxy/env restore only what is marked as
rem PTor-managed (a foreign WinDivert service is likewise left alone), but
rem DNS is poison-aware and unconditional: any interface still pointing at
rem 127.0.0.1 / ::1 is reverted (good backup restored, poisoned or missing
rem backup reverted to DHCP) even when the Managed marker is already gone,
rem because a poisoned backup would otherwise restore loopback right back.
rem Requires administrator rights: re-launches itself via UAC when needed.
setlocal
cd /d "%~dp0"

net session >nul 2>nul
if errorlevel 1 (
  echo Requesting administrator rights, please approve the UAC prompt...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)

tasklist /FI "IMAGENAME eq PTor.exe" 2>nul | find /i "PTor.exe" >nul
if not errorlevel 1 (
  echo WARNING: PTor.exe seems to be running. Close it first for a clean repair.
  set /p "CONT=Continue anyway? [y/N] "
  if /i not "%CONT%"=="y" exit /b 2
)

echo --- system proxy ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; try { $st=(Get-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction Stop).PTorState | ConvertFrom-Json; if ($st.HasAutoBackup) { $curU=(Get-ItemProperty -LiteralPath $k -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL; $curD=(Get-ItemProperty -LiteralPath $k -Name AutoDetect -ErrorAction SilentlyContinue).AutoDetect; if ([string]::IsNullOrEmpty($curU) -and ($null -eq $curD -or [int]$curD -eq 0)) { if ([string]::IsNullOrEmpty($st.SavedAutoConfigUrl)) { Remove-ItemProperty -LiteralPath $k -Name AutoConfigURL -ErrorAction SilentlyContinue } else { Set-ItemProperty -LiteralPath $k -Name AutoConfigURL -Value ([string]$st.SavedAutoConfigUrl) -Type String }; Set-ItemProperty -LiteralPath $k -Name AutoDetect -Value ([int]$st.SavedAutoDetect) -Type DWord; Write-Output 'PROXY-AUTO: PAC and auto-detect settings restored.' } else { Write-Output 'PROXY-AUTO: auto-config changed elsewhere, left untouched.' } } } catch { Write-Output 'PROXY-AUTO: nothing to restore.' }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $m=Get-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; if ($m -and $m.PTorManaged -eq 1) { $ok=$false; try { $st=(Get-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction Stop).PTorState | ConvertFrom-Json; $curS=(Get-ItemProperty -LiteralPath $k -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer; if ($curS -ceq $st.AppliedServer) { Set-ItemProperty -LiteralPath $k -Name ProxyEnable -Value ([int]$st.Saved.Enabled) -Type DWord; if ([string]::IsNullOrEmpty($st.Saved.Server)) { Remove-ItemProperty -LiteralPath $k -Name ProxyServer -ErrorAction SilentlyContinue } else { Set-ItemProperty -LiteralPath $k -Name ProxyServer -Value ([string]$st.Saved.Server) -Type String }; if ([string]::IsNullOrEmpty($st.Saved.Override)) { Remove-ItemProperty -LiteralPath $k -Name ProxyOverride -ErrorAction SilentlyContinue } else { Set-ItemProperty -LiteralPath $k -Name ProxyOverride -Value ([string]$st.Saved.Override) -Type String }; $ok=$true } else { Write-Output 'PROXY: current settings are no longer PTor ones, left untouched.'; $ok=$true } } catch { Write-Output 'PROXY: saved state unreadable, values left untouched.' }; Remove-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction SilentlyContinue; if (-not ('Win32.Wininet' -as [type])) { Add-Type -Namespace Win32 -Name Wininet -MemberDefinition ('[DllImport(' + [char]34 + 'wininet.dll' + [char]34 + ')]public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int l);') }; [Win32.Wininet]::InternetSetOption(0,39,0,0); [Win32.Wininet]::InternetSetOption(0,37,0,0); if ($ok) { Write-Output 'PROXY: previous settings restored.' } else { Write-Output 'PROXY: marker cleared.' } } else { Write-Output 'PROXY: not managed by PTor, nothing to do.' }"

echo --- environment variables ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$store='HKCU:\Software\PTor'; $env='HKCU:\Environment'; $m=Get-ItemProperty -LiteralPath $store -Name EnvManaged -ErrorAction SilentlyContinue; if ($m -and $m.EnvManaged -eq 1) { $n=0; $left=@(); try { $st=(Get-ItemProperty -LiteralPath $store -Name EnvState -ErrorAction Stop).EnvState | ConvertFrom-Json; foreach ($p in $st.Applied.PSObject.Properties) { $cur=(Get-ItemProperty -LiteralPath $env -Name $p.Name -ErrorAction SilentlyContinue).($p.Name); if ($cur -ceq $p.Value) { $sv=$st.Saved.($p.Name); if ($null -ne $sv -and $null -ne $sv.V) { $t=if ([int]$sv.K -eq 2) { 'ExpandString' } else { 'String' }; Set-ItemProperty -LiteralPath $env -Name $p.Name -Value ([string]$sv.V) -Type $t } else { Remove-ItemProperty -LiteralPath $env -Name $p.Name -ErrorAction SilentlyContinue }; $n++ } else { $left+=$p.Name } } } catch { Write-Output 'ENV: saved state unreadable, values left as-is.' }; Remove-ItemProperty -LiteralPath $store -Name EnvManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $store -Name EnvState -ErrorAction SilentlyContinue; Write-Output ('ENV: restored ' + $n + ' vars, left ' + $left.Count + ' changed elsewhere untouched.') } else { Write-Output 'ENV: not managed by PTor, nothing to do.' }"

rem setx broadcasts WM_SETTINGCHANGE so running Explorer picks up restored env vars.
setx PTOR_RESCUE_PING 1 >nul 2>nul
reg delete HKCU\Environment /v PTOR_RESCUE_PING /f >nul 2>nul
echo --- dns resolvers (HKLM, poison-aware) ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$base='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'; $store='HKLM:\SOFTWARE\PTor\Dns'; $fixed=0; $poison=0; try { $names=(Get-ChildItem -LiteralPath $base -ErrorAction Stop | Select-Object -ExpandProperty PSChildName); foreach ($g in $names) { try { $cur=(Get-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue).NameServer } catch { continue }; if ($cur -ceq '127.0.0.1') { $had=$false; $orig=$null; $kraw=$null; try { $props=(Get-ItemProperty -LiteralPath $store -ErrorAction Stop).PSObject.Properties.Name; $had=$props -contains ('Backup_'+$g) } catch { $had=$false }; if ($had) { try { $orig=(Get-ItemProperty -LiteralPath $store -Name ('Backup_'+$g) -ErrorAction SilentlyContinue).('Backup_'+$g); $kraw=(Get-ItemProperty -LiteralPath $store -Name ('BackupKind_'+$g) -ErrorAction SilentlyContinue).('BackupKind_'+$g) } catch { $had=$false } }; if ($had -and ([string]$orig) -ceq '127.0.0.1') { Remove-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue; $poison++; $fixed++ } elseif ($had) { try { $kt=if ([int]$kraw -eq 2) { 'ExpandString' } else { 'String' }; Set-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -Value ([string]$orig) -Type $kt; $fixed++ } catch { Write-Output ('DNS: failed on '+$g) } } else { Remove-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue; $fixed++ } } }; Write-Output ('DNSv4: fixed '+$fixed+' interface(s)'+($(if ($poison -gt 0) { ' ('+$poison+' had poisoned 127.0.0.1 backups, reverted to DHCP)' } else { '' })) + '.') } catch { Write-Output 'DNSv4: restore failed (need admin?), values left as-is.' }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$base='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces'; $store='HKLM:\SOFTWARE\PTor\Dns'; $fixed=0; $poison=0; try { $names=(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName); if ($names) { foreach ($g in $names) { try { $cur=(Get-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue).NameServer } catch { continue }; if ($cur -ceq '::1') { $had=$false; $orig=$null; $kraw=$null; try { $props=(Get-ItemProperty -LiteralPath $store -ErrorAction Stop).PSObject.Properties.Name; $had=$props -contains ('Backup6_'+$g) } catch { $had=$false }; if ($had) { try { $orig=(Get-ItemProperty -LiteralPath $store -Name ('Backup6_'+$g) -ErrorAction SilentlyContinue).('Backup6_'+$g); $kraw=(Get-ItemProperty -LiteralPath $store -Name ('BackupKind6_'+$g) -ErrorAction SilentlyContinue).('BackupKind6_'+$g) } catch { $had=$false } }; if ($had -and ([string]$orig) -ceq '::1') { Remove-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue; $poison++; $fixed++ } elseif ($had) { try { $kt=if ([int]$kraw -eq 2) { 'ExpandString' } else { 'String' }; Set-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -Value ([string]$orig) -Type $kt; $fixed++ } catch { Write-Output ('DNSv6: failed on '+$g) } } else { Remove-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue; $fixed++ } } } }; Write-Output ('DNSv6: fixed '+$fixed+' interface(s)'+($(if ($poison -gt 0) { ' ('+$poison+' had poisoned ::1 backups, reverted to DHCP)' } else { '' })) + '.') } catch { Write-Output 'DNSv6: restore failed (need admin?), values left as-is.' }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$store='HKLM:\SOFTWARE\PTor\Dns'; try { Get-Item -LiteralPath $store -ErrorAction Stop | Select-Object -ExpandProperty Property | Where-Object { $_ -eq 'Managed' -or $_ -eq 'Ipv6Applied' -or $_ -like 'Backup*' } | ForEach-Object { Remove-ItemProperty -LiteralPath $store -Name $_ -ErrorAction SilentlyContinue }; Write-Output 'DNS markers cleared.' } catch { Write-Output 'DNS markers: nothing to clear.' }"
ipconfig /flushdns >nul 2>nul
echo DNS cache flushed.

echo --- windivert driver service ---
sc query WinDivert >nul 2>nul
if errorlevel 1 (
  echo Driver service not installed, nothing to do.
) else (
  rem Same concept as Uninstall.exe: only ours goes (image path match or our
  rem checkpoint says we created it). A foreign service is left untouched.
  call :IsOursService
  if not errorlevel 1 (
    sc stop WinDivert >nul 2>nul
    sc delete WinDivert >nul 2>nul
    echo PTor's driver service removed. A reboot clears it if still marked for deletion.
  ) else (
    echo A WinDivert service exists but is NOT PTor's - left untouched. Remove it manually ^(sc delete WinDivert^) only if you know which app installed it.
  )
)

echo --- checkpoint ---
rem AFTER the driver check above: :IsOursService reads this file, so deleting
rem first would blind the ownership check to the image-path literal only.
del "%ProgramData%\PTor\checkpoint.json" >nul 2>nul
echo Checkpoint cleared if present.

echo --- fallback cleanup (proxy env / WinHTTP with no markers left) ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$names=@('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'); $n=0; foreach ($nm in $names) { $v=[Environment]::GetEnvironmentVariable($nm,'User'); if ($v -and $v -like '*127.0.0.1:9080*') { [Environment]::SetEnvironmentVariable($nm,$null,'User'); $n++ } }; foreach ($nm in $names) { $v=[Environment]::GetEnvironmentVariable($nm,'Machine'); if ($v -and $v -like '*127.0.0.1:9080*') { [Environment]::SetEnvironmentVariable($nm,$null,'Machine'); $n++ } }; if ($n -gt 0) { Write-Output ('FALLBACK ENV: cleared ' + $n + ' leftover proxy variable(s) pointing at 127.0.0.1:9080.') } else { Write-Output 'FALLBACK ENV: no leftover 127.0.0.1:9080 proxy variables found.' }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$cur=netsh winhttp show proxy; if ($cur -match '127\.0\.0\.1:9080') { netsh winhttp reset proxy | Out-Null; Write-Output 'FALLBACK PROXY: WinHTTP proxy was still set to 127.0.0.1:9080, reset to direct access.' } else { Write-Output 'FALLBACK PROXY: WinHTTP proxy not pointing at 127.0.0.1:9080, left as-is.' }"

echo --- verify ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$bad=0; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object { $v=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$_.PSChildName) -Name NameServer -ErrorAction SilentlyContinue).NameServer; if ($v -ceq '127.0.0.1') { $bad++ } }; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object { $v=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\'+$_.PSChildName) -Name NameServer -ErrorAction SilentlyContinue).NameServer; if ($v -ceq '::1') { $bad++ } }; Write-Output ('loopback DNS left: ' + $bad + ' interface(s) (0 means clean)'); if ($bad -eq 0) { Write-Output 'OK: DNS looks clean. If pages still fail, restart the browser (it caches the old proxy/DNS).' } else { Write-Output 'STILL BROKEN: loopback DNS remains - re-run this script as administrator.' }"
echo ---
echo Done. Restart apps and browsers so they pick up the restored settings.
echo If any environment variables were cleared above, close ALL open terminal
echo windows and open a new one before testing - existing sessions cache the
echo old values and will not reflect the fix until reopened.
pause
endlocal
exit /b 0

rem %1 unused. Succeeds (errorlevel 0) only if the WinDivert service is ours:
rem its image points at this install's tools\WinDivert sys, or our checkpoint
rem says we created it. Anything else (or unreadable) fails safe: keep it.
:IsOursService
set "WIMG="
for /f "tokens=1* delims=:" %%A in ('sc qc WinDivert 2^>nul ^| findstr /i /c:"BINARY_PATH_NAME"') do set "WIMG=%%B"
if not defined WIMG exit /b 1
for /f "tokens=*" %%C in ("%WIMG%") do set "WIMG=%%C"
set "WIMG=%WIMG:"=%"
if /i "%WIMG:~0,4%"=="\\?\" set "WIMG=%WIMG:~4%"
if /i "%WIMG:~0,4%"=="\??\" set "WIMG=%WIMG:~4%"
if /i "%WIMG%"=="%~dp0tools\WinDivert\x64\WinDivert64.sys" exit /b 0
if /i "%WIMG%"=="%~dp0tools\WinDivert\x86\WinDivert32.sys" exit /b 0
echo %WIMG% | findstr /i /c:"\PTor\tools\WinDivert\" >nul 2>nul
if not errorlevel 1 exit /b 0
findstr /m /c:"\"DriverService\":\"created\"" "%ProgramData%\PTor\checkpoint.json" >nul 2>nul
if not errorlevel 1 exit /b 0
exit /b 1
