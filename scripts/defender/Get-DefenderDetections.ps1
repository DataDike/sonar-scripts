#Requires -Version 5.1
<#
.SYNOPSIS
    Lists recent Microsoft Defender detections and flags the ones not remediated.

.DESCRIPTION
    Read-only. Reads Get-MpThreatDetection and Get-MpThreat and lists the detections of the last
    -Days days, newest first: time (local), threat name, severity, status and the first resource
    path, truncated to 120 characters (paths may contain a user name). At most 20 detections are
    listed and the output is kept under 4 KB.

    A detection is "active" when its status is not cleaned (2), quarantined (3), removed (4) or
    blocked (6); allowed (5) and failed actions count as active.

    Exit codes:
      0 no detection, or all detections remediated.
      1 the detections could not be read.
      2 at least one active (not remediated) detection.
      3 Defender is not available on this machine.

.PARAMETER Days
    How many days back to look. Default 7.

.EXAMPLE
    -Days 30

.NOTES
    Name:       Defender - Recent detections
    GUID:       39fd4124-d357-41cc-876b-4019a30096e4
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL | 2 WARN | 3 NOT APPLICABLE
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$Days = 7
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$remediatedIds = @(2, 3, 4, 6)
$statusNames = @{ 0 = 'unknown'; 1 = 'detected'; 2 = 'cleaned'; 3 = 'quarantined'; 4 = 'removed'; 5 = 'allowed'; 6 = 'blocked';
                  102 = 'quarantine failed'; 103 = 'remove failed'; 104 = 'allow failed'; 105 = 'abandoned'; 107 = 'block failed' }
$severityNames = @{ 0 = 'unknown'; 1 = 'low'; 2 = 'moderate'; 4 = 'high'; 5 = 'severe' }
$maxOutput = 3800

function Get-ShortText([string]$text, [int]$max) {
    if ($null -eq $text) { return '' }
    $t = ($text -replace '[^\x20-\x7E]', '?').Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }
    return $t
}

$exitCode = 0
try {
    if (-not (Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue) -or
        -not (Get-Service -Name WinDefend -ErrorAction SilentlyContinue)) {
        Write-Output 'INFO: Microsoft Defender is not available on this machine (not applicable)'
        exit 3
    }

    $since = (Get-Date).AddDays(-1 * [math]::Abs($Days))
    try {
        $all = @(Get-MpThreatDetection -ErrorAction Stop)
    } catch {
        $m = $_.Exception.Message
        if ($m -match 'No MSFT_MpThreatDetection|not found') { $all = @() }
        else { Write-Output ('FAIL: cannot read Defender detections: ' + (Get-ShortText $m 200)); exit 1 }
    }
    $recent = @($all | Where-Object { $_.InitialDetectionTime -and $_.InitialDetectionTime -ge $since } |
                Sort-Object -Property InitialDetectionTime -Descending)

    if ($recent.Count -eq 0) {
        Write-Output ("OK: no Defender detection in the last {0} days" -f $Days)
        exit 0
    }

    $threats = @{}
    try { Get-MpThreat -ErrorAction Stop | ForEach-Object { $threats[[string]$_.ThreatID] = $_ } } catch { $null = $_ }

    $active = @($recent | Where-Object { $remediatedIds -notcontains [int]$_.ThreatStatusID })
    if ($active.Count) {
        $exitCode = 2
        $verdict = "WARN: {0} active (not remediated) detection(s) in the last {1} days, {2} in total" -f $active.Count, $Days, $recent.Count
    } else {
        $verdict = "OK: {0} detection(s) in the last {1} days, all remediated" -f $recent.Count, $Days
    }
    Write-Output $verdict
    $used = $verdict.Length

    $shown = 0
    foreach ($d in ($recent | Select-Object -First 20)) {
        $t = $threats[[string]$d.ThreatID]
        $name = if ($t -and $t.ThreatName) { $t.ThreatName } else { 'threat id ' + $d.ThreatID }
        $sev = 'unknown'
        if ($t -and $severityNames.ContainsKey([int]$t.SeverityID)) { $sev = $severityNames[[int]$t.SeverityID] }
        $sid = [int]$d.ThreatStatusID
        $status = if ($statusNames.ContainsKey($sid)) { $statusNames[$sid] } else { "status $sid" }
        $prefix = if ($remediatedIds -contains $sid) { 'INFO' } else { 'WARN' }
        $res = ''
        $first = @($d.Resources) | Where-Object { $_ } | Select-Object -First 1
        if ($first) { $res = Get-ShortText ([string]$first) 120 }
        $line = "{0}: {1} | {2} | {3} | {4} | {5}" -f $prefix, ([datetime]$d.InitialDetectionTime).ToString('yyyy-MM-dd HH:mm'),
                (Get-ShortText $name 60), $sev, $status, $res
        if ($used + $line.Length + 2 -gt $maxOutput) { break }
        Write-Output $line
        $used += $line.Length + 2
        $shown++
    }
    if ($shown -lt $recent.Count) { Write-Output ("INFO: {0} more detection(s) not listed" -f ($recent.Count - $shown)) }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
