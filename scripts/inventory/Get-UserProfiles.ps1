#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the local user profiles with last use, loaded state, size and stale flag.

.DESCRIPTION
    Reads Win32_UserProfile (special system profiles excluded). For each profile: account name
    (SID translated; the SID is shown when the account no longer exists), last use time, loaded or
    not, and the size of the profile folder. The size is the sum of the files below the folder
    (links and junctions are not followed; cloud-only OneDrive files count with their full size).
    Sizing all profiles shares one time budget (-MaxSeconds); a size cut by the budget or by
    folders that cannot be read is marked "partial". Pass -SkipSize to skip sizing.
    A profile is stale when it is not loaded and its last use is older than -StaleDays.
    Note: Windows may update the last use time for reasons other than a logon.
    Read-only; nothing is deleted. Exit 0, or 2 with -WarnOnStale when a stale profile exists.

.PARAMETER StaleDays
    Days without use after which a profile is reported as stale. Default 90.

.PARAMETER WarnOnStale
    Use as a check: exit 2 (WARN) when at least one stale profile exists. Default off (exit 0).

.PARAMETER SkipSize
    Do not measure the profile folders (fast). Default off.

.PARAMETER MaxSeconds
    Total time budget in seconds for measuring the folders. Default 120.

.EXAMPLE
    -StaleDays 60 -WarnOnStale -MaxSeconds 90

.NOTES
    Name:       Inventory - User profiles
    GUID:       75c95ed7-c8ac-4604-a7fa-35cde704e697
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); without admin rights other profiles' sizes are partial
    Exit codes: 0 OK | 1 FAIL (error) | 2 WARN (stale profile, only with -WarnOnStale)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90,
    [switch]$WarnOnStale,
    [switch]$SkipSize,
    [int]$MaxSeconds = 120
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output must stay ASCII: Windows returns localized text (accents are stripped).
function ConvertTo-AsciiText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return ([regex]::Replace($n, '[^\x20-\x7E]', '')).Trim()
}

function Test-AccessDenied($ErrorRecord) {
    return ($ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or
        [string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied|0x80070005')
}

$inv = [System.Globalization.CultureInfo]::InvariantCulture
function Format-Size([long]$Bytes) {
    if ($Bytes -ge 1GB) { return [string]::Format($inv, '{0:0.0} GB', $Bytes / 1GB) }
    return [string]::Format($inv, '{0:0} MB', $Bytes / 1MB)
}

# Sums file sizes below $Path without following reparse points; stops when the clock passes $Limit.
function Measure-Folder([string]$Path, [System.Diagnostics.Stopwatch]$Clock, [double]$Limit) {
    $total = [long]0
    $partial = $false
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $stack.Push((New-Object System.IO.DirectoryInfo($Path)))
    $reparse = [System.IO.FileAttributes]::ReparsePoint
    while ($stack.Count) {
        if ($Clock.Elapsed.TotalSeconds -ge $Limit) { $partial = $true; break }
        $d = $stack.Pop()
        try {
            foreach ($f in $d.GetFiles()) { $total += $f.Length }
            foreach ($sub in $d.GetDirectories()) {
                if (-not ($sub.Attributes -band $reparse)) { $stack.Push($sub) }
            }
        }
        catch { $partial = $true }
    }
    return [pscustomobject]@{ Bytes = $total; Partial = $partial }
}

$exitCode = 0
try {
    if ($StaleDays -lt 1) { $StaleDays = 90 }
    if ($MaxSeconds -lt 1) { $MaxSeconds = 120 }

    try { $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = False' -ErrorAction Stop) }
    catch {
        if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading user profiles (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
        throw
    }
    if (-not $profiles.Count) {
        Write-Output 'OK: no local user profile found'
        $host.SetShouldExit(0); exit 0
    }

    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $totalBytes = [long]0
    $anyPartial = $false
    foreach ($p in $profiles) {
        $sid = [string]$p.SID
        $name = $sid
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $name = $sid + ' (' + (Split-Path -Leaf ([string]$p.LocalPath)) + ', account not found)' }
        $last = $p.LastUseTime
        $stale = (-not $p.Loaded -and $last -and $last -lt $cutoff)
        $size = '-'
        if (-not $SkipSize) {
            if (-not $p.LocalPath -or -not (Test-Path -LiteralPath ([string]$p.LocalPath))) { $size = 'folder missing' }
            elseif ($clock.Elapsed.TotalSeconds -ge $MaxSeconds) { $size = 'not measured (time budget)'; $anyPartial = $true }
            else {
                $m = Measure-Folder ([string]$p.LocalPath) $clock $MaxSeconds
                $totalBytes += $m.Bytes
                $size = Format-Size $m.Bytes
                if ($m.Partial) { $size += ' partial'; $anyPartial = $true }
            }
        }
        $rows.Add([pscustomobject]@{
            Name = $name; Last = $last; Loaded = [bool]$p.Loaded; Stale = [bool]$stale; Size = $size
        }) | Out-Null
    }

    $staleRows = @($rows | Where-Object { $_.Stale })
    $loaded = @($rows | Where-Object { $_.Loaded }).Count
    $sizeText = if ($SkipSize) { 'size skipped' } elseif ($anyPartial) { 'total at least ' + (Format-Size $totalBytes) } else { 'total ' + (Format-Size $totalBytes) }
    if ($WarnOnStale -and $staleRows.Count) {
        $names = ($staleRows | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', '
        Write-Output (ConvertTo-AsciiText ('WARN: {0} stale profile(s) not used for more than {1} days: {2}' -f $staleRows.Count, $StaleDays, $names))
        $exitCode = 2
    }
    else {
        Write-Output ('OK: {0} profile(s), {1} loaded, {2} stale (over {3} days), {4}' -f $rows.Count, $loaded, $staleRows.Count, $StaleDays, $sizeText)
    }

    $budget = 3700
    $printed = 0
    $sorted = @($rows | Sort-Object -Property @{ Expression = { if ($_.Last) { $_.Last } else { [datetime]::MinValue } }; Descending = $true })
    foreach ($r in $sorted) {
        $lastText = if ($r.Last) { $r.Last.ToString('yyyy-MM-dd HH:mm', $inv) } else { 'unknown' }
        $flags = @()
        if ($r.Loaded) { $flags += 'loaded' } else { $flags += 'not loaded' }
        if ($r.Stale) { $flags += 'STALE' }
        $line = ConvertTo-AsciiText ('INFO: {0} | last use {1} | {2} | {3}' -f $r.Name, $lastText, ($flags -join ', '), $r.Size)
        if (($budget - ($line.Length + 2)) -lt 0) { break }
        $budget -= ($line.Length + 2)
        Write-Output $line
        $printed++
    }
    if ($printed -lt $sorted.Count) { Write-Output ('INFO: {0} more not shown' -f ($sorted.Count - $printed)) }
    if ($anyPartial) { Write-Output ('INFO: partial = time budget of {0}s reached or folders not readable (run as SYSTEM for full sizes)' -f $MaxSeconds) }
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading user profiles (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not read user profiles: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
