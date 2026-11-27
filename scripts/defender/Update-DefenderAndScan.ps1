#Requires -Version 5.1
<#
.SYNOPSIS
    Updates Microsoft Defender signatures and runs a quick or full scan.

.DESCRIPTION
    Action script (on demand or scheduled task). It runs Update-MpSignature from the configured
    update sources, then optionally Start-MpScan, and reports the signature/engine versions before
    and after and the detections recorded since the scan started (Get-MpThreatDetection).
    It changes no setting and removes nothing itself; remediation is done by Defender according
    to its own policy.

    Timeout: the manifest default is 1800 seconds. A full scan on a large disk can take longer;
    raise the timeout up to 3600 seconds (the library maximum) when using -ScanType Full.

    Exit codes:
      0 signatures updated and the scan found nothing.
      1 the scan failed, or a detection was not remediated.
      2 the signature update failed, or detections were found and all remediated.
      3 Defender is not available on this machine.

.PARAMETER ScanType
    Quick (default), Full or None (update only).

.EXAMPLE
    -ScanType Full

.NOTES
    Name:       Defender - Update and scan
    GUID:       2c23af3c-230b-4a5d-8925-3ed3854148df
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
    [ValidateSet('Quick', 'Full', 'None')]
    [string]$ScanType = 'Quick'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ThreatStatusID values that mean the threat was handled: 2 cleaned, 3 quarantined, 4 removed, 6 blocked
$remediatedIds = @(2, 3, 4, 6)
$lines = New-Object System.Collections.Generic.List[string]
$script:isFail = $false
$script:isWarn = $false

function Get-ShortText([string]$text, [int]$max) {
    if ($null -eq $text) { return '' }
    $t = ($text -replace '[^\x20-\x7E]', '?').Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }
    return $t
}

$exitCode = 0
try {
    if (-not (Get-Command -Name Update-MpSignature -ErrorAction SilentlyContinue) -or
        -not (Get-Service -Name WinDefend -ErrorAction SilentlyContinue)) {
        Write-Output 'INFO: Microsoft Defender is not available on this machine (not applicable)'
        $host.SetShouldExit(3); exit 3
    }
    try { $before = Get-MpComputerStatus -ErrorAction Stop } catch {
        Write-Output ('INFO: Microsoft Defender is not active: ' + (Get-ShortText $_.Exception.Message 150))
        $host.SetShouldExit(3); exit 3
    }

    # 1. Signature update
    try {
        Update-MpSignature -ErrorAction Stop
        $after = Get-MpComputerStatus -ErrorAction Stop
        if ($after.AntivirusSignatureVersion -ne $before.AntivirusSignatureVersion) {
            $lines.Add(("OK: signatures {0} -> {1}" -f $before.AntivirusSignatureVersion, $after.AntivirusSignatureVersion))
        } else {
            $lines.Add(("OK: signatures already current ({0})" -f $after.AntivirusSignatureVersion))
        }
        $lines.Add(("INFO: engine {0} -> {1}, product {2} -> {3}" -f $before.AMEngineVersion, $after.AMEngineVersion, $before.AMProductVersion, $after.AMProductVersion))
    } catch {
        $script:isWarn = $true
        $lines.Add(("WARN: signature update failed: {0} (signatures {1})" -f (Get-ShortText $_.Exception.Message 150), $before.AntivirusSignatureVersion))
    }

    # 2. Scan
    if ($ScanType -eq 'None') {
        $lines.Add('INFO: scan skipped (-ScanType None)')
    } else {
        $start = (Get-Date).AddSeconds(-5)
        $scanOk = $true
        try {
            Start-MpScan -ScanType ($ScanType + 'Scan') -ErrorAction Stop
            $mins = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)
            $lines.Add(("OK: {0} scan completed in {1} min" -f $ScanType, $mins))
        } catch {
            $scanOk = $false
            $script:isFail = $true
            $lines.Add(("FAIL: {0} scan failed: {1}" -f $ScanType, (Get-ShortText $_.Exception.Message 150)))
        }

        if ($scanOk) {
            $detections = @()
            try {
                $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $start })
            } catch {
                $lines.Add('INFO: detections not readable: ' + (Get-ShortText $_.Exception.Message 120))
            }
            $names = @{}
            if ($detections.Count) {
                try { Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName } } catch { $null = $_ }
            }
            $active = @($detections | Where-Object { $remediatedIds -notcontains [int]$_.ThreatStatusID })
            $lines.Add(("INFO: threats found since scan start: {0} ({1} not remediated)" -f $detections.Count, $active.Count))
            foreach ($d in ($detections | Select-Object -First 10)) {
                $n = $names[[string]$d.ThreatID]
                if (-not $n) { $n = 'threat id ' + $d.ThreatID }
                $state = if ($remediatedIds -contains [int]$d.ThreatStatusID) { 'remediated' } else { 'NOT remediated' }
                $lines.Add(("INFO:   {0}: {1}, status id {2}" -f (Get-ShortText $n 80), $state, $d.ThreatStatusID))
            }
            if ($active.Count) { $script:isFail = $true }
            elseif ($detections.Count) { $script:isWarn = $true }
        }
    }

    if ($script:isFail) { $exitCode = 1; Write-Output 'FAIL: Defender scan failed or left threats not remediated' }
    elseif ($script:isWarn) { $exitCode = 2; Write-Output 'WARN: Defender update/scan finished with warnings' }
    elseif ($ScanType -eq 'None') { Write-Output 'OK: Defender signatures updated (no scan)' }
    else { Write-Output 'OK: Defender signatures updated and no threat found' }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
