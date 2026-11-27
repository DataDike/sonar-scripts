#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the Windows Time service, the time source, the last synchronization and the clock offset.

.DESCRIPTION
    Reads the W32Time service state and "w32tm /query /status" (time source, stratum, last
    successful sync), then measures the clock offset with one NTP sample:
        w32tm /stripchart /computer:<source> /samples:1 /dataonly
    against the configured source when it is a server name, otherwise against -Reference.
    w32tm prints localized labels, so /query /status is parsed by line position (Leap, Stratum,
    Precision, Root Delay, Root Dispersion, ReferenceId, Last Sync, Source, Poll Interval; the
    same order in every language) and numbers by regex. The last sync time is read in the
    current culture; when it cannot be read it counts as "never synchronized".
    With -Resync the service is started when needed (start type is not changed) and
    "w32tm /resync /rediscover" is run (w32tm has no /force option). Nothing else is changed.
    Use it as a check.

.PARAMETER MaxOffsetSeconds
    Maximum accepted clock offset in seconds. Default 60.

.PARAMETER Reference
    NTP server used to measure the offset when the configured source is not a server name
    (Local CMOS Clock, Free-running System Clock, VM IC provider), or always when given.
    Default 'time.windows.com'.

.PARAMETER Resync
    Start W32Time if it is stopped and force a resynchronization before checking.

.EXAMPLE
    -MaxOffsetSeconds 60

.EXAMPLE
    -Resync -Reference 'pool.ntp.org'

.NOTES
    Name:       Maintenance - Time synchronization
    GUID:       e2117acd-d1eb-42ac-882a-bc7137a3fe6b
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator; -Resync needs it)
    Exit codes: 0 OK | 1 FAIL (offset above maximum, service stopped, or error) |
                2 WARN (last sync older than 7 days, never synced or offset not measurable) |
                3 NOT APPLICABLE (W32Time service absent)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxOffsetSeconds = 60,
    [string]$Reference = 'time.windows.com',
    [switch]$Resync
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# w32tm prints dates in the local culture; numbers in the output use the invariant culture
$localCulture = [System.Globalization.CultureInfo]::CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-Ascii([string]$Text) {
    if (-not $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return [regex]::Replace($n, '[^\x20-\x7E]', '')
}

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

# Runs w32tm and returns its output lines; ExitCode in $script:w32Code
function Invoke-W32tm([string[]]$Arguments) {
    $out = @(& w32tm.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $script:w32Code = $LASTEXITCODE
    return $out
}

# Parses "w32tm /query /status" by position: value after the first ': ' of each label line
function Get-W32Status {
    $out = Invoke-W32tm @('/query', '/status')
    $r = [pscustomobject]@{ Ok = $false; Stratum = $null; LastSyncText = ''; LastSync = $null; Source = ''; Raw = '' }
    $vals = @($out | Where-Object { $_ -match '^\S[^:]*:\s' } | ForEach-Object { ($_ -split ':\s', 2)[1].Trim() })
    if ($script:w32Code -ne 0 -or $vals.Count -lt 8) {
        $r.Raw = ConvertTo-Ascii ((@($out | Where-Object { $_.Trim() }) | Select-Object -Last 1) -join '')
        return $r
    }
    $r.Ok = $true
    $m = [regex]::Match($vals[1], '^\d+')
    if ($m.Success) { $r.Stratum = [int]$m.Value }
    $r.LastSyncText = $vals[6]
    $r.Source = ($vals[7] -replace ',0x[0-9a-fA-F]+$', '').Trim()
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($vals[6], $localCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt) -or
        [datetime]::TryParse($vals[6], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
        if ($dt.Year -gt 2000) { $r.LastSync = $dt }
    }
    return $r
}

$script:w32Code = 0
$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
$fails = New-Object System.Collections.Generic.List[string]
$warns = New-Object System.Collections.Generic.List[string]
try {
    $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Output 'INFO: NOT APPLICABLE: Windows Time service (W32Time) is not installed'
        $host.SetShouldExit(3); exit 3
    }

    if ($Resync) {
        if ($svc.Status -ne 'Running') {
            if ($svc.StartType -eq 'Disabled') { $lines.Add('WARN: W32Time is Disabled; not started (start type is not changed)') }
            else {
                try {
                    Start-Service -InputObject $svc -ErrorAction Stop
                    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                    $lines.Add('OK: W32Time started')
                }
                catch { $lines.Add(('WARN: W32Time could not be started: ' + $_.Exception.Message)) }
            }
        }
        $svc.Refresh()
        if ($svc.Status -eq 'Running') {
            $rs = Invoke-W32tm @('/resync', '/rediscover')
            if ($script:w32Code -eq 0) { $lines.Add('OK: resynchronization requested and completed') }
            else {
                $lines.Add(("WARN: w32tm /resync failed (exit {0}): {1}" -f $script:w32Code, (ConvertTo-Ascii ((@($rs | Where-Object { $_.Trim() }) | Select-Object -Last 1) -join ''))))
            }
        }
    }

    $svc.Refresh()
    $lines.Add(("INFO: W32Time {0} (start {1})" -f $svc.Status, $svc.StartType))
    if ($svc.Status -ne 'Running') { $fails.Add('W32Time service is not running (use -Resync to start it)') }

    # --- Status --------------------------------------------------------------------------
    $st = Get-W32Status
    $source = ''
    if ($st.Ok) {
        $source = $st.Source
        $lines.Add(("INFO: source {0}, stratum {1}" -f $st.Source, $st.Stratum))
        if ($st.LastSync) {
            $ageDays = ((Get-Date) - $st.LastSync).TotalDays
            $lines.Add(("INFO: last successful sync {0} ({1:0.0} day(s) ago)" -f $st.LastSync.ToString('yyyy-MM-dd HH:mm'), $ageDays))
            if ($ageDays -gt 7) { $warns.Add(("last successful sync {0:0} day(s) ago" -f $ageDays)) }
        }
        else {
            $lines.Add(('INFO: last successful sync: ' + $st.LastSyncText))
            $warns.Add('the clock has never synchronized (or the sync time is unreadable)')
        }
        if ($st.Stratum -eq 0) { $lines.Add('INFO: stratum 0: no valid time source in use') }
    }
    elseif ($svc.Status -eq 'Running') {
        $lines.Add(('WARN: w32tm /query /status failed: ' + $st.Raw))
        $warns.Add('time status not readable')
    }

    # --- Offset --------------------------------------------------------------------------
    $target = $Reference
    if (-not $PSBoundParameters.ContainsKey('Reference') -and $source -match '^[A-Za-z0-9][A-Za-z0-9.\-:\[\]]*$' -and $source -notmatch '^(Local|Free|VM)') {
        $target = $source
    }
    $sc = Invoke-W32tm @('/stripchart', ('/computer:' + $target), '/samples:1', '/dataonly')
    $offset = $null
    foreach ($l in $sc) {
        $m = [regex]::Match($l, ',\s*([+-]?\d+(?:[.,]\d+)?)s\s*$')
        if ($m.Success) {
            $offset = [double]::Parse(($m.Groups[1].Value -replace ',', '.'), [System.Globalization.CultureInfo]::InvariantCulture)
            break
        }
    }
    if ($null -ne $offset) {
        $lines.Add(("INFO: offset against {0}: {1:+0.000;-0.000} s (maximum {2} s)" -f $target, $offset, $MaxOffsetSeconds))
        if ([math]::Abs($offset) -gt $MaxOffsetSeconds) {
            $fails.Add(("clock is {0:0.0} s off {1} (maximum {2} s)" -f [math]::Abs($offset), $target, $MaxOffsetSeconds))
        }
    }
    else {
        $errText = ConvertTo-Ascii ((@($sc | Where-Object { $_.Trim() }) | Select-Object -Last 1) -join '')
        $lines.Add(("WARN: offset against {0} not measured (NTP UDP 123 blocked or server down): {1}" -f $target, $errText))
        $warns.Add('offset not measurable')
    }

    if ($fails.Count -gt 0) { $exitCode = 1; $verdict = 'FAIL: ' + ($fails -join '; ') }
    elseif ($warns.Count -gt 0) { $exitCode = 2; $verdict = 'WARN: ' + ($warns -join '; ') }
    else { $verdict = "OK: time synchronized with {0}, offset {1:0.000} s" -f $source, $offset }
    Write-Report $verdict $lines
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
