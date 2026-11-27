#Requires -Version 5.1
<#
.SYNOPSIS
    Summarizes critical and error events of the last hours, grouped by source and event id.

.DESCRIPTION
    Reads the System and Application logs (or the logs given in -LogName) for events of level
    1 (critical) and 2 (error) written in the last -Hours hours, at most 2000 events per log
    (newest first). Events are grouped by log, provider and event id; the 15 largest groups are
    listed with their count, the time of the latest event and the first line of its message
    (100 characters at most). Messages are localized by Windows and are reduced to ASCII.
    Read only. Use it as a check: exits 2 when any error was found, 1 with -FailOnCritical when a
    critical event was found, 0 when the logs are clean.

.PARAMETER LogName
    Comma separated list of event logs. Default 'System,Application'. The Security log needs
    administrator rights.

.PARAMETER Hours
    How many hours back to look. Default 24.

.PARAMETER FailOnCritical
    Exit 1 (FAIL) instead of 2 (WARN) when at least one critical (level 1) event was found.

.EXAMPLE
    -Hours 24

.EXAMPLE
    -LogName 'System' -Hours 6 -FailOnCritical

.NOTES
    Name:       Troubleshooting - Event log errors
    GUID:       908d2c47-bd3b-47ac-b394-f739d72abfd3
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (critical with -FailOnCritical, or error) | 2 WARN (errors found)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string]$LogName = 'System,Application',
    [int]$Hours = 24,
    [switch]$FailOnCritical
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

# Windows returns localized text: everything printed goes through this ASCII filter
function ConvertTo-Ascii([string]$Text) {
    if (-not $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return [regex]::Replace($n, '[^\x20-\x7E]', '')
}

# Prints the verdict and the detail lines, keeping the whole output under 4 KB
function Write-Report([string]$Verdict, $Lines) {
    $size = $Verdict.Length + 2
    Write-Output $Verdict
    foreach ($l in $Lines) {
        $t = ConvertTo-Ascii $l
        if ($size + $t.Length + 2 -gt 3900) { Write-Output 'INFO: output truncated'; break }
        $size += $t.Length + 2
        Write-Output $t
    }
}

$maxEvents = 2000
$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    if ($Hours -lt 1) { $Hours = 1 }
    $start = (Get-Date).AddHours(-$Hours)
    $logs = @($LogName -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($logs.Count -eq 0) { $logs = @('System', 'Application') }

    $all = New-Object System.Collections.Generic.List[object]
    $perLog = New-Object System.Collections.Generic.List[string]
    $readErrors = 0
    foreach ($log in $logs) {
        $found = @()
        try {
            $found = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2; StartTime = $start } -MaxEvents $maxEvents -ErrorAction Stop)
        }
        catch {
            $id = [string]$_.FullyQualifiedErrorId
            if ($id -like 'NoMatchingEventsFound*') { $found = @() }
            elseif ($id -like 'NoMatchingLogsFound*') { $readErrors++; $lines.Add("WARN: log '$log' does not exist"); continue }
            else { $readErrors++; $lines.Add(("WARN: log '{0}' not readable: {1}" -f $log, $_.Exception.Message)); continue }
        }
        $cap = ''
        if ($found.Count -ge $maxEvents) { $cap = '+' }
        $perLog.Add(("{0} {1}{2}" -f $log, $found.Count, $cap))
        foreach ($e in $found) {
            $all.Add([pscustomobject]@{
                    Key      = ('{0}|{1}|{2}' -f $log, $e.ProviderName, $e.Id)
                    Log      = $log
                    Provider = [string]$e.ProviderName
                    Id       = $e.Id
                    Level    = [int]$e.Level
                    Time     = $e.TimeCreated
                    Record   = $e
                })
        }
    }

    $critical = @($all | Where-Object { $_.Level -eq 1 }).Count
    $groups = @($all | Group-Object -Property Key | Sort-Object -Property Count -Descending)
    $shown = 0
    foreach ($g in $groups) {
        if ($shown -ge 15) { break }
        $shown++
        $latest = $g.Group | Sort-Object -Property Time -Descending | Select-Object -First 1
        $msg = ''
        try { $msg = [string]$latest.Record.Message } catch { $msg = '' }
        if (-not $msg) { $msg = '(no message text; provider not installed)' }
        $msg = ConvertTo-Ascii ((($msg -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1))
        $msg = $msg.Trim()
        if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 97) + '...' }
        $sev = 'error'
        if (@($g.Group | Where-Object { $_.Level -eq 1 }).Count -gt 0) { $sev = 'CRITICAL' }
        $lines.Add(("INFO: {0} {1} id {2}: {3}x {4}, last {5}: {6}" -f $latest.Log, $latest.Provider, $latest.Id, $g.Count, $sev, $latest.Time.ToString('yyyy-MM-dd HH:mm'), $msg))
    }
    if ($groups.Count -gt $shown) { $lines.Add(("INFO: ... {0} smaller group(s) not listed" -f ($groups.Count - $shown))) }

    if ($perLog.Count -eq 0) { $perLog.Add('no log read') }
    $summary = "{0} error/critical event(s) in {1} h ({2}), {3} critical, {4} distinct source(s)" -f $all.Count, $Hours, ($perLog -join ', '), $critical, $groups.Count
    if ($FailOnCritical -and $critical -gt 0) { $exitCode = 1; $verdict = 'FAIL: ' + $summary }
    elseif ($all.Count -gt 0 -or $readErrors -gt 0) { $exitCode = 2; $verdict = 'WARN: ' + $summary }
    else { $verdict = 'OK: ' + $summary }
    Write-Report $verdict $lines
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
