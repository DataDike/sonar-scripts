#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies (default) or repairs the Windows component store and protected system files.

.DESCRIPTION
    Default (verification only, changes nothing):
        DISM /Online /Cleanup-Image /ScanHealth   then   sfc /verifyonly
    With -Repair:
        DISM /Online /Cleanup-Image /RestoreHealth   then   sfc /scannow
    DISM runs with /English so its result can be parsed on any Windows language. sfc output is
    localized and written in UTF-16: it is captured to a temporary file, matched against the
    English phrases and, on other languages, the [SR] lines that sfc adds to CBS.log during the
    run (CBS.log is always English). RestoreHealth may download repair sources from Windows
    Update. Both tools can take 10 to 30 minutes each; never reboots.
    Use it as an action, or as a weekly check in verify mode.

.PARAMETER Repair
    Run DISM /RestoreHealth and sfc /scannow instead of the read-only verification.

.EXAMPLE
    (no arguments: verification only)

.EXAMPLE
    -Repair

.NOTES
    Name:       Maintenance - System file repair
    GUID:       14028b19-367f-430f-b2d4-f8780278988a
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator required)
    Exit codes: 0 OK (healthy or repaired) | 1 FAIL (corruption not repaired, or error) |
                2 WARN (corruption found in verify mode, or repaired and a reboot is needed)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$Repair
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
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

# 32-bit PowerShell on 64-bit Windows must use Sysnative to reach the real DISM / sfc
function Get-SystemTool([string]$Exe) {
    $dir = Join-Path $env:SystemRoot 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $dir = Join-Path $env:SystemRoot 'Sysnative'
    }
    return (Join-Path $dir $Exe)
}

# Reads the part of CBS.log written after $Offset (shared read, the log stays open by CBS)
function Get-CbsTail([string]$Path, [int64]$Offset) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        if ($fs.Length -lt $Offset) { $Offset = 0 }
        $len = $fs.Length - $Offset
        if ($len -gt 50MB) { $Offset = $fs.Length - 50MB; $len = 50MB }
        $fs.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($fs)
        return $reader.ReadToEnd()
    }
    catch { return '' }
    finally { if ($fs) { $fs.Dispose() } }
}

$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
$mode = 'verify'
if ($Repair) { $mode = 'repair' }
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Report 'FAIL: administrator rights are required (DISM and sfc refuse to run); nothing was checked' $lines
        $host.SetShouldExit(1); exit 1
    }

    # --- DISM ----------------------------------------------------------------------------
    $dismArg = '/ScanHealth'
    if ($Repair) { $dismArg = '/RestoreHealth' }
    $dism = Get-SystemTool 'dism.exe'
    $t0 = Get-Date
    $dismOut = (& $dism /Online /Cleanup-Image $dismArg /English /NoRestart 2>&1 | Out-String)
    $dismCode = $LASTEXITCODE
    $dismMin = ((Get-Date) - $t0).TotalMinutes

    $dismState = 'unknown'
    if ($dismOut -match 'No component store corruption detected') { $dismState = 'healthy' }
    elseif ($dismOut -match 'component store corruption was repaired') { $dismState = 'repaired' }
    elseif ($dismOut -match 'component store is repairable') { $dismState = 'repairable' }
    elseif ($dismOut -match 'not repairable|source files could not be found|could not be downloaded') { $dismState = 'notrepairable' }
    elseif ($Repair -and $dismCode -eq 0 -and $dismOut -match 'restore operation completed successfully') { $dismState = 'healthy' }
    if ($dismCode -ne 0 -and $dismCode -ne 3010 -and $dismState -ne 'notrepairable') { $dismState = 'error' }

    $errLine = ''
    $m = [regex]::Match($dismOut, '(?m)^Error:\s*(\S+)')
    if ($m.Success) { $errLine = ' error ' + $m.Groups[1].Value }
    $lines.Add(("INFO: DISM {0}: {1} (exit {2}{3}, {4:0.0} min)" -f $dismArg, $dismState, $dismCode, $errLine, $dismMin))

    # --- sfc -----------------------------------------------------------------------------
    $sfcArg = '/verifyonly'
    if ($Repair) { $sfcArg = '/scannow' }
    $sfc = Get-SystemTool 'sfc.exe'
    $cbsLog = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    $cbsOffset = 0L
    if (Test-Path -LiteralPath $cbsLog) { $cbsOffset = (Get-Item -LiteralPath $cbsLog).Length }
    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('sonar-sfc-' + [guid]::NewGuid().ToString('N') + '.txt'))
    $sfcText = ''
    $sfcCode = -1
    $t0 = Get-Date
    try {
        $p = Start-Process -FilePath $sfc -ArgumentList $sfcArg -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp
        $sfcCode = $p.ExitCode
        if ([System.IO.File]::Exists($tmp)) {
            $sfcText = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::Unicode)
        }
    }
    finally {
        try { if ([System.IO.File]::Exists($tmp)) { [System.IO.File]::Delete($tmp) } }
        catch { Write-Verbose ('temporary file kept: ' + $tmp) }
    }
    $sfcMin = ((Get-Date) - $t0).TotalMinutes
    $sfcText = ($sfcText -replace "`0", '') -replace '\s+', ' '

    $sfcState = 'unknown'
    if ($sfcText -match 'did not find any integrity violations') { $sfcState = 'clean' }
    elseif ($sfcText -match 'successfully repaired') { $sfcState = 'repaired' }
    elseif ($sfcText -match 'unable to fix') { $sfcState = 'unrepaired' }
    elseif ($sfcText -match 'found integrity violations') { $sfcState = 'violations' }
    elseif ($sfcText -match 'repair pending|could not perform the requested operation|could not start the repair service') { $sfcState = 'error' }
    $how = 'sfc text'
    if ($sfcState -eq 'unknown') {
        # non-English Windows: use the [SR] lines that sfc wrote to CBS.log during this run
        $how = 'CBS.log'
        $tail = Get-CbsTail $cbsLog $cbsOffset
        $sr = @(($tail -split "`r?`n") | Where-Object { $_ -match '\[SR\]' })
        $cannot = @($sr | Where-Object { $_ -match 'Cannot repair' }).Count
        $fixed = @($sr | Where-Object { $_ -match 'Repairing corrupted file|Repaired file' }).Count
        $corrupt = @($sr | Where-Object { $_ -match 'corrupt|hash mismatch|Cannot verify' }).Count
        $done = @($sr | Where-Object { $_ -match 'Verify complete|Repair complete' }).Count
        if ($cannot -gt 0) { $sfcState = 'unrepaired' }
        elseif ($Repair -and $fixed -gt 0) { $sfcState = 'repaired' }
        elseif ($corrupt -gt 0) { if ($Repair) { $sfcState = 'unrepaired' } else { $sfcState = 'violations' } }
        elseif ($done -gt 0 -and $sfcCode -eq 0) { $sfcState = 'clean' }
        elseif ($sr.Count -eq 0 -and $sfcCode -ne 0) { $sfcState = 'error' }
    }
    $lines.Add(("INFO: sfc {0}: {1} (exit {2}, read from {3}, {4:0.0} min)" -f $sfcArg, $sfcState, $sfcCode, $how, $sfcMin))

    # --- Reboot state --------------------------------------------------------------------
    $rebootPending = ($dismCode -eq 3010) -or
        (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    if ($rebootPending) { $lines.Add('INFO: a reboot is pending for servicing (this script never reboots)') }
    $lines.Add('INFO: details in %SystemRoot%\Logs\DISM\dism.log and %SystemRoot%\Logs\CBS\CBS.log')

    # --- Verdict -------------------------------------------------------------------------
    $bad = @('notrepairable', 'error', 'unrepaired')
    if (($bad -contains $dismState) -or ($bad -contains $sfcState)) {
        $exitCode = 1
        $verdict = "FAIL: system file {0} found problems that were not repaired (DISM {1}, sfc {2})" -f $mode, $dismState, $sfcState
    }
    elseif (-not $Repair -and ($dismState -eq 'repairable' -or $sfcState -eq 'violations')) {
        $exitCode = 2
        $verdict = "WARN: corruption found (DISM {0}, sfc {1}); run with -Repair" -f $dismState, $sfcState
    }
    elseif ($Repair -and ($dismState -eq 'repaired' -or $sfcState -eq 'repaired') -and ($rebootPending -or $sfcState -eq 'repaired')) {
        $exitCode = 2
        $verdict = "WARN: system files repaired (DISM {0}, sfc {1}); reboot to complete" -f $dismState, $sfcState
    }
    elseif ($dismState -eq 'unknown' -or $sfcState -eq 'unknown') {
        $exitCode = 2
        $verdict = "WARN: result could not be read (DISM {0}, sfc {1}); check the logs" -f $dismState, $sfcState
    }
    elseif ($dismState -eq 'repaired' -or $sfcState -eq 'repaired') {
        $verdict = "OK: system files repaired (DISM {0}, sfc {1})" -f $dismState, $sfcState
    }
    else {
        $verdict = "OK: component store and system files healthy (DISM {0}, sfc {1})" -f $dismState, $sfcState
    }
    Write-Report $verdict $lines
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
