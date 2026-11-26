#Requires -Version 5.1
<#
.SYNOPSIS
    Lists listening TCP (and optionally UDP) ports with the owning process and services.

.DESCRIPTION
    Reads Get-NetTCPConnection -State Listen (and Get-NetUDPEndpoint with -IncludeUdp) and prints one
    line per protocol / local address / port with the owning process name and the Windows services
    hosted by that process. Lines are de-duplicated, sorted by port and capped at 60 (and about 3.5 KB of output).
    With -AlertOnPort the script works as a check: it fails when any of those ports is listening on
    a non-loopback address (for example RDP 3389 or SMB 445 exposed). Read-only.

.PARAMETER IncludeUdp
    Also list UDP endpoints. Default off (UDP lists are long).

.PARAMETER AlertOnPort
    Ports that must not listen on a non-loopback address. When one does, exit 1. Default: none.
    Accepts a list or one comma-separated string ("3389,445").

.EXAMPLE
    -AlertOnPort 3389,445

.EXAMPLE
    -IncludeUdp

.NOTES
    Name:       Network - Listening ports
    GUID:       b129b67b-0037-4f3c-bb8d-a7d6a3e343d3
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator recommended to see every owning process)
    Exit codes: 0 OK | 1 FAIL (an -AlertOnPort port is exposed, or error)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$IncludeUdp,
    [string[]]$AlertOnPort = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

function Test-Loopback([string]$Address) {
    if ($Address -eq '::1') { return $true }
    if ($Address -match '^127\.') { return $true }
    if ($Address -match '^::ffff:127\.') { return $true }
    return $false
}

# Normalize -AlertOnPort: a list, or one "3389,445" string when passed through -File
$alertPorts = @()
foreach ($item in $AlertOnPort) {
    foreach ($tok in ([string]$item -split '[,;\s]+')) {
        if (-not $tok) { continue }
        $v = 0
        if ([int]::TryParse($tok, [ref]$v) -and $v -ge 1 -and $v -le 65535) { $alertPorts += $v }
        else { Write-Line ('FAIL: invalid port in -AlertOnPort: ' + $tok); exit 1 }
    }
}

$maxLines = 60
$maxBytes = 3500   # keep the whole output under 4 KB
$exitCode = 0
try {
    # Process id -> name
    $procNames = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $procNames[[int]$p.Id] = $p.ProcessName }

    # Process id -> service names (svchost hosts many)
    $svcByPid = @{}
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter 'ProcessId <> 0' -Property Name, ProcessId -ErrorAction Stop)) {
            $k = [int]$s.ProcessId
            if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.Generic.List[string] }
            $svcByPid[$k].Add([string]$s.Name) | Out-Null
        }
    }
    catch {
        Write-Verbose ('service map unavailable: ' + $_.Exception.Message)
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $rows.Add([pscustomobject]@{ Proto = 'TCP'; Address = [string]$c.LocalAddress; Port = [int]$c.LocalPort; ProcId = [int]$c.OwningProcess }) | Out-Null
    }
    if ($IncludeUdp) {
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            $rows.Add([pscustomobject]@{ Proto = 'UDP'; Address = [string]$u.LocalAddress; Port = [int]$u.LocalPort; ProcId = [int]$u.OwningProcess }) | Out-Null
        }
    }

    # De-duplicate on protocol + address + port + pid
    $seen = @{}
    $unique = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $key = '{0}|{1}|{2}|{3}' -f $r.Proto, $r.Address, $r.Port, $r.ProcId
        if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $unique.Add($r) | Out-Null }
    }
    $sorted = @($unique | Sort-Object -Property Port, Proto, Address)

    # Alert evaluation
    $exposed = New-Object System.Collections.Generic.List[string]
    foreach ($port in $alertPorts) {
        $hits = @($sorted | Where-Object { $_.Port -eq $port -and -not (Test-Loopback $_.Address) })
        foreach ($h in $hits) {
            $item = '{0} {1}:{2}' -f $h.Proto, $h.Address, $h.Port
            if (-not $exposed.Contains($item)) { $exposed.Add($item) | Out-Null }
        }
    }

    $tcpCount = @($sorted | Where-Object { $_.Proto -eq 'TCP' }).Count
    $udpCount = @($sorted | Where-Object { $_.Proto -eq 'UDP' }).Count
    $summary = '{0} TCP listener(s)' -f $tcpCount
    if ($IncludeUdp) { $summary += (', {0} UDP endpoint(s)' -f $udpCount) }

    if ($exposed.Count) {
        Write-Line ('FAIL: port(s) exposed on a non-loopback address: ' + ($exposed -join ', '))
        $exitCode = 1
    }
    elseif ($alertPorts.Count) {
        Write-Line ('OK: none of port(s) {0} listening on a non-loopback address; {1}' -f ($alertPorts -join ','), $summary)
    }
    else {
        Write-Line ('OK: ' + $summary)
    }

    $n = 0
    $bytes = 0
    foreach ($r in $sorted) {
        if ($n -ge $maxLines -or $bytes -ge $maxBytes) { break }
        $pname = if ($procNames.ContainsKey($r.ProcId)) { $procNames[$r.ProcId] } else { 'unknown' }
        if ($r.ProcId -eq 4) { $pname = 'System' }
        $svc = ''
        if ($svcByPid.ContainsKey($r.ProcId)) {
            $list = @($svcByPid[$r.ProcId])
            $svc = ' svc=' + (($list | Select-Object -First 4) -join ',')
            if ($list.Count -gt 4) { $svc += ',+' + ($list.Count - 4) }
        }
        $line = 'INFO: {0} {1}:{2} pid {3} {4}{5}' -f $r.Proto, $r.Address, $r.Port, $r.ProcId, $pname, $svc
        Write-Line $line
        $bytes += $line.Length + 2
        $n++
    }
    if ($sorted.Count -gt $n) { Write-Line ('INFO: {0} more line(s) not shown' -f ($sorted.Count - $n)) }
}
catch {
    Write-Line ('FAIL: ' + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
