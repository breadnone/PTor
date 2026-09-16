# PTor DNS smoke test (Phase 1). Run ELEVATED with PTor routing + lockdown ON.
# Read-only: resolves names and inspects registry, changes nothing.
# Manual restore check: toggle lockdown off, then diff interface NameServer
# values against what they were (they must be byte-identical to pre-run).
$ErrorActionPreference = 'Continue'
$fail = 0
function Check($name, [scriptblock]$body) {
    try {
        $result = & $body
        if ($result) { Write-Host "PASS: $name" -ForegroundColor Green }
        else { Write-Host "FAIL: $name" -ForegroundColor Red; $script:fail++ }
    } catch {
        Write-Host "FAIL: $name ($($_.Exception.Message))" -ForegroundColor Red
        $script:fail++
    }
}

Check 'Tor DNSPort listening on 127.0.0.1:9053' {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect('127.0.0.1', 9053, $null, $null)
        $iar.AsyncWaitHandle.WaitOne(3000) -and $c.Connected
    } finally { $c.Close() }
}

Check 'System resolver answers (via Tor)' {
    (Resolve-DnsName example.com -Type A -ErrorAction Stop | Where-Object { $_.IPAddress }).Count -ge 1
}

Check '.onion resolves (only possible through Tor)' {
    # DuckDuckGo v3 onion, long-lived well-known address.
    $ips = Resolve-DnsName 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczadfs6ta6d.onion' -Type A -ErrorAction Stop |
        Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
    $ips.Count -ge 1
}

Check 'Forced external resolver is fail-closed (8.8.8.8 times out, no clearnet answer)' {
    try {
        Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -ErrorAction Stop | Out-Null
        $false  # an answer here would mean a clearnet leak
    } catch { $true }
}

function Test-NxDomain($name) {
    # Must NXDOMAIN (local answer, never forwarded): $true = good.
    try {
        Resolve-DnsName $name -DnsOnly -ErrorAction Stop | Out-Null
        return $false
    } catch {
        return ($_.Exception.Message -match 'not exist|NXDOMAIN|NameNotFound|not found')
    }
}

Check 'Special-use names NXDOMAIN locally (no internal-name leak to exits)' {
    (Test-NxDomain 'smoke-probe-xyz.invalid') -and (Test-NxDomain 'smoke-probe-xyz.local')
}

Check 'All interfaces point at 127.0.0.1' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    $bad = @()
    foreach ($guid in (Get-ChildItem $base -ErrorAction Stop).PSChildName) {
        $ns = (Get-ItemProperty "$base\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
        if ($ns -ne '127.0.0.1') { $bad += "$guid=$ns" }
    }
    if ($bad.Count -gt 0) { Write-Host "  off-interfaces: $($bad -join '; ')" -ForegroundColor Yellow }
    $bad.Count -eq 0
}

if ($fail -eq 0) { Write-Host 'ALL DNS SMOKE TESTS PASSED' -ForegroundColor Green; exit 0 }
else { Write-Host "$fail TEST(S) FAILED" -ForegroundColor Red; exit 1 }
