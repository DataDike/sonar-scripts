#Requires -Version 5.1
<#
.SYNOPSIS
    Reports blue screens, unexpected shutdowns, minidumps and application crashes of the last days.

.DESCRIPTION
    Reads the System log for bug checks (Microsoft-Windows-WER-SystemErrorReporting 1001, with
    the bug check code), unexpected power loss (Microsoft-Windows-Kernel-Power 41) and dirty
    shutdowns (EventLog 6008), lists the minidump files in %SystemRoot%\Minidump and summarizes
    application crashes (Application Error 1000) grouped by faulting application (top 10).
    Events that happen within 15 minutes of each other are counted as ONE incident, because a
    single blue screen usually logs 41, 6008 and 1001 together at the next boot.
    Read only: nothing is changed. Use it as a check: the number of incidents (blue screens plus
    unexpected shutdowns) is compared with -WarnCount and -FailCount.

.PARAMETER Days
    How many days back to look. Default 30.

.PARAMETER WarnCount
    Incidents (blue screens plus unexpected shutdowns) that raise a warning. Default 1.

.PARAMETER FailCount
    Incidents (blue screens plus unexpected shutdowns) that raise a failure. Default 3.

.EXAMPLE
    -Days 30 -WarnCount 1 -FailCount 3

.NOTES
    Name:       Troubleshooting - Crashes and unexpected shutdowns
    GUID:       d3a670dc-bef0-43e7-826d-2629ae799ad9
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); minidumps are not readable without administrator rights
    Exit codes: 0 OK | 1 FAIL (incidents >= FailCount or error) | 2 WARN (incidents >= WarnCount)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$Days = 30,
    [int]$WarnCount = 1,
    [int]$FailCount = 3
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

# Get-WinEvent throws when nothing matches; that is not an error here
function Get-EventSafe([hashtable]$Filter, [int]$Max) {
    try {
        return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop)
    }
    catch {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    if ($Days -lt 1) { $Days = 1 }
    if ($WarnCount -lt 1) { $WarnCount = 1 }
    if ($FailCount -lt $WarnCount) { $FailCount = $WarnCount }
    $start = (Get-Date).AddDays(-$Days)

    # --- System log: bug checks and unexpected shutdowns ----------------------------------
    $raw = New-Object System.Collections.Generic.List[object]
    foreach ($ev in (Get-EventSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $start } 200)) {
        $code = ''
        $src = ''
        if ($ev.Properties.Count -gt 0) { $src = [string]$ev.Properties[0].Value }
        if (-not $src) { $src = [string]$ev.Message }
        $m = [regex]::Match($src, '0x[0-9a-fA-F]{8}')
        if ($m.Success) { $code = $m.Value.ToLowerInvariant() }
        $raw.Add([pscustomobject]@{ Time = $ev.TimeCreated; Kind = 'bugcheck'; Code = $code })
    }
    foreach ($ev in (Get-EventSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $start } 200)) {
        $code = ''
        if ($ev.Properties.Count -gt 0) {
            $bc = 0L
            if ([int64]::TryParse([string]$ev.Properties[0].Value, [ref]$bc) -and $bc -ne 0) { $code = '0x{0:x8}' -f $bc }
        }
        $raw.Add([pscustomobject]@{ Time = $ev.TimeCreated; Kind = 'kp41'; Code = $code })
    }
    foreach ($ev in (Get-EventSafe @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $start } 200)) {
        $raw.Add([pscustomobject]@{ Time = $ev.TimeCreated; Kind = 'ev6008'; Code = '' })
    }

    # Merge events logged within 15 minutes of each other into one incident
    $incidents = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($r in ($raw | Sort-Object -Property Time)) {
        if ($current -and (($r.Time - $current.Last).TotalMinutes -le 15)) {
            $current.Last = $r.Time
            $current.Kinds += $r.Kind
            if ($r.Code -and -not $current.Code) { $current.Code = $r.Code }
            continue
        }
        $current = [pscustomobject]@{ Time = $r.Time; Last = $r.Time; Kinds = @($r.Kind); Code = $r.Code }
        $incidents.Add($current)
    }
    $bsod = 0
    foreach ($i in $incidents) {
        if (($i.Kinds -contains 'bugcheck') -or $i.Code) { $bsod++ }
    }
    $unexpected = $incidents.Count - $bsod

    $shown = 0
    foreach ($i in ($incidents | Sort-Object -Property Time -Descending)) {
        if ($shown -ge 10) { $lines.Add(("INFO: ... {0} older incident(s) not listed" -f ($incidents.Count - $shown))); break }
        $shown++
        $events = (($i.Kinds | Sort-Object -Unique) | ForEach-Object {
                switch ($_) { 'bugcheck' { 'WER 1001' } 'kp41' { 'Kernel-Power 41' } default { 'EventLog 6008' } }
            }) -join ', '
        if (($i.Kinds -contains 'bugcheck') -or $i.Code) {
            $what = 'blue screen'
            if ($i.Code) { $what = 'blue screen, bug check ' + $i.Code }
        }
        else { $what = 'unexpected shutdown (power loss, hang or forced off)' }
        $lines.Add(("INFO: {0} {1} [{2}]" -f $i.Time.ToString('yyyy-MM-dd HH:mm'), $what, $events))
    }

    # --- Minidumps --------------------------------------------------------------------------
    $dumpDir = Join-Path $env:SystemRoot 'Minidump'
    if (Test-Path -LiteralPath $dumpDir -PathType Container) {
        try {
            $dumps = @(Get-ChildItem -LiteralPath $dumpDir -Filter '*.dmp' -File -Force -ErrorAction Stop |
                    Sort-Object -Property LastWriteTime -Descending)
            $recent = @($dumps | Where-Object { $_.LastWriteTime -ge $start })
            $lines.Add(("INFO: minidumps: {0} in the period, {1} in total" -f $recent.Count, $dumps.Count))
            foreach ($d in ($recent | Select-Object -First 5)) {
                $lines.Add(("INFO: minidump {0} {1} ({2:0} KB)" -f $d.Name, $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), ($d.Length / 1KB)))
            }
        }
        catch { $lines.Add('INFO: minidump folder not readable (administrator rights required)') }
    }
    else { $lines.Add('INFO: no minidump folder') }

    # --- Application crashes ----------------------------------------------------------------
    $appEvents = Get-EventSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $start } 2000
    $capNote = ''
    if ($appEvents.Count -ge 2000) { $capNote = ' (capped at the newest 2000 events)' }
    $lines.Add(("INFO: application crashes: {0} in {1} day(s){2}" -f $appEvents.Count, $Days, $capNote))
    $apps = @($appEvents | ForEach-Object {
            $name = ''
            if ($_.Properties.Count -gt 0) { $name = [string]$_.Properties[0].Value }
            if (-not $name) { $name = 'unknown' }
            [pscustomobject]@{ App = $name.ToLowerInvariant(); Time = $_.TimeCreated }
        } | Group-Object -Property App | Sort-Object -Property Count -Descending | Select-Object -First 10)
    foreach ($g in $apps) {
        $last = ($g.Group | Sort-Object -Property Time -Descending | Select-Object -First 1).Time
        $lines.Add(("INFO: app crash {0}: {1}x, last {2}" -f $g.Name, $g.Count, $last.ToString('yyyy-MM-dd HH:mm')))
    }

    # --- Verdict ----------------------------------------------------------------------------
    $summary = "{0} incident(s) in {1} day(s): {2} blue screen(s), {3} unexpected shutdown(s); {4} application crash(es)" -f $incidents.Count, $Days, $bsod, $unexpected, $appEvents.Count
    if ($incidents.Count -ge $FailCount) { $exitCode = 1; $verdict = 'FAIL: ' + $summary }
    elseif ($incidents.Count -ge $WarnCount) { $exitCode = 2; $verdict = 'WARN: ' + $summary }
    else { $verdict = 'OK: ' + $summary }
    Write-Report $verdict $lines
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
