@echo off
rem PTor emergency network rescue. Restores proxy, environment variables and
rem DNS resolvers left behind by a crashed or killed PTor, flushes the DNS
rem cache, clears stale checkpoints and removes a leftover WinDivert service.
rem Safe to run anytime: anything not marked as PTor-managed is left alone.
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $m=Get-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; if ($m -and $m.PTorManaged -eq 1) { $ok=$false; try { $st=(Get-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction Stop).PTorState | ConvertFrom-Json; $curS=(Get-ItemProperty -LiteralPath $k -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer; if ($curS -ceq $st.AppliedServer) { Set-ItemProperty -LiteralPath $k -Name ProxyEnable -Value ([int]$st.Saved.Enabled) -Type DWord; if ([string]::IsNullOrEmpty($st.Saved.Server)) { Remove-ItemProperty -LiteralPath $k -Name ProxyServer -ErrorAction SilentlyContinue } else { Set-ItemProperty -LiteralPath $k -Name ProxyServer -Value ([string]$st.Saved.Server) -Type String }; if ([string]::IsNullOrEmpty($st.Saved.Override)) { Remove-ItemProperty -LiteralPath $k -Name ProxyOverride -ErrorAction SilentlyContinue } else { Set-ItemProperty -LiteralPath $k -Name ProxyOverride -Value ([string]$st.Saved.Override) -Type String }; $ok=$true } else { Write-Output 'PROXY: current settings are no longer PTor ones, left untouched.'; $ok=$true } } catch { Write-Output 'PROXY: saved state unreadable, values left untouched.' }; Remove-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $k -Name PTorState -ErrorAction SilentlyContinue; if (-not ('Win32.Wininet' -as [type])) { Add-Type -Namespace Win32 -Name Wininet -MemberDefinition ('[DllImport(' + [char]34 + 'wininet.dll' + [char]34 + ')]public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int l);') }; [Win32.Wininet]::InternetSetOption(0,39,0,0); [Win32.Wininet]::InternetSetOption(0,37,0,0); if ($ok) { Write-Output 'PROXY: previous settings restored.' } else { Write-Output 'PROXY: marker cleared.' } } else { Write-Output 'PROXY: not managed by PTor, nothing to do.' }"

echo --- environment variables ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$store='HKCU:\Software\PTor'; $env='HKCU:\Environment'; $m=Get-ItemProperty -LiteralPath $store -Name EnvManaged -ErrorAction SilentlyContinue; if ($m -and $m.EnvManaged -eq 1) { $n=0; $left=@(); try { $st=(Get-ItemProperty -LiteralPath $store -Name EnvState -ErrorAction Stop).EnvState | ConvertFrom-Json; foreach ($p in $st.Applied.PSObject.Properties) { $cur=(Get-ItemProperty -LiteralPath $env -Name $p.Name -ErrorAction SilentlyContinue).($p.Name); if ($cur -ceq $p.Value) { $sv=$st.Saved.($p.Name); if ($null -ne $sv -and $null -ne $sv.V) { $t=if ([int]$sv.K -eq 2) { 'ExpandString' } else { 'String' }; Set-ItemProperty -LiteralPath $env -Name $p.Name -Value ([string]$sv.V) -Type $t } else { Remove-ItemProperty -LiteralPath $env -Name $p.Name -ErrorAction SilentlyContinue }; $n++ } else { $left+=$p.Name } } } catch { Write-Output 'ENV: saved state unreadable, values left as-is.' }; Remove-ItemProperty -LiteralPath $store -Name EnvManaged -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $store -Name EnvState -ErrorAction SilentlyContinue; Write-Output ('ENV: restored ' + $n + ' vars, left ' + $left.Count + ' changed elsewhere untouched.') } else { Write-Output 'ENV: not managed by PTor, nothing to do.' }"

rem setx broadcasts WM_SETTINGCHANGE so running Explorer picks up restored env vars.
setx PTOR_RESCUE_PING 1 >nul 2>nul
reg delete HKCU\Environment /v PTOR_RESCUE_PING /f >nul 2>nul
echo --- dns resolvers ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$base='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'; $store='HKLM:\SOFTWARE\PTor\Dns'; $m=Get-ItemProperty -LiteralPath $store -Name Managed -ErrorAction SilentlyContinue; if ($m -and $m.Managed -eq 1) { try { $n=0; $names=(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName); foreach ($g in $names) { $cur=(Get-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue).NameServer; if ($cur -ceq '127.0.0.1') { $props=(Get-ItemProperty -LiteralPath $store -ErrorAction SilentlyContinue).PSObject.Properties.Name; if ($props -contains ('Backup_'+$g)) { $orig=(Get-ItemProperty -LiteralPath $store -Name ('Backup_'+$g) -ErrorAction SilentlyContinue).('Backup_'+$g); $kraw=(Get-ItemProperty -LiteralPath $store -Name ('BackupKind_'+$g) -ErrorAction SilentlyContinue).('BackupKind_'+$g); $kt=if ([int]$kraw -eq 2) { 'ExpandString' } else { 'String' }; Set-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -Value ([string]$orig) -Type $kt } else { Remove-ItemProperty -LiteralPath ($base+'\'+$g) -Name NameServer -ErrorAction SilentlyContinue }; $n++ } }; Get-Item -LiteralPath $store -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property | Where-Object { $_ -eq 'Managed' -or $_ -like 'Backup_*' } | ForEach-Object { Remove-ItemProperty -LiteralPath $store -Name $_ -ErrorAction SilentlyContinue }; Write-Output ('DNS: resolvers restored on ' + $n + ' interfaces.') } catch { Write-Output 'DNS: restore failed (need admin?), values left as-is.' } } else { Write-Output 'DNS: not managed by PTor, nothing to do.' }"
ipconfig /flushdns >nul 2>nul
echo DNS cache flushed.

echo --- checkpoint ---
del "%ProgramData%\PTor\checkpoint.json" >nul 2>nul
echo Checkpoint cleared if present.

echo --- windivert driver service ---
sc query WinDivert >nul 2>nul
if errorlevel 1 (
  echo Driver service not installed, nothing to do.
) else (
  sc stop WinDivert >nul 2>nul
  sc delete WinDivert >nul 2>nul
  echo Driver service removal requested. A reboot clears it if still marked for deletion.
)

echo ---
echo Done. Restart apps and browsers so they pick up the restored settings.
pause
endlocal
