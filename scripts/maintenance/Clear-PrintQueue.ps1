#Requires -Version 5.1
<#
.SYNOPSIS
    Lists print jobs per printer and (with -DryRun:$false) clears a stuck print queue.

.DESCRIPTION
    Lists the jobs of every local printer (Get-PrintJob): count, jobs in error and the oldest job.
    Document names are never printed. A job is "stuck" when its status contains Error, Blocked,
    Offline, PaperOut, UserIntervention or Deleting, or when it was submitted more than
    -StuckMinutes minutes ago.
    With -DryRun:$false the Print Spooler service is stopped, the spool files (*.SPL and *.SHD
    only) in %SystemRoot%\System32\spool\PRINTERS are deleted and the Spooler is ALWAYS started
    again in a finally block (unless it is disabled). Nothing else is touched: printers, drivers
    and ports stay as they are. With -OnlyStuck nothing is done unless a stuck job exists.
    Default is a dry run that only reports. Use it as an action.

.PARAMETER OnlyStuck
    Clear the queue only when at least one job is stuck; otherwise do nothing.

.PARAMETER StuckMinutes
    Age in minutes after which a job counts as stuck. Default 30.

.PARAMETER DryRun
    Report only. Default is $true; pass -DryRun:$false to stop the Spooler and delete the
    spool files.

.EXAMPLE
    (no arguments: dry run, lists the queues)

.EXAMPLE
    -OnlyStuck -StuckMinutes 30 -DryRun:$false

.NOTES
    Name:       Maintenance - Clear print queue
    GUID:       f2d15b5e-905a-43d3-936c-20c928525ae4
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (error, files left or Spooler not running at the end) |
                3 NOT APPLICABLE (Print Spooler service absent)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$OnlyStuck,
    [int]$StuckMinutes = 30,
    [switch]$DryRun = $true
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

$reparse = [System.IO.FileAttributes]::ReparsePoint
$spoolDir = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'

# Only *.SPL / *.SHD files directly in the PRINTERS folder, never links
function Get-SpoolFile {
    $dir = New-Object System.IO.DirectoryInfo($spoolDir)
    if (-not $dir.Exists -or ($dir.Attributes -band $reparse)) { return @() }
    return @($dir.GetFiles() | Where-Object {
            -not ($_.Attributes -band $reparse) -and ($_.Extension -eq '.SPL' -or $_.Extension -eq '.SHD')
        })
}

$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler) {
        Write-Output 'INFO: NOT APPLICABLE: Print Spooler service is not installed'
        $host.SetShouldExit(3); exit 3
    }
    if ($StuckMinutes -lt 1) { $StuckMinutes = 1 }
    $cutoff = (Get-Date).AddMinutes(-$StuckMinutes)
    $lines.Add(("INFO: Spooler {0} (start {1})" -f $spooler.Status, $spooler.StartType))

    # --- Jobs per printer ---------------------------------------------------------------------
    $totalJobs = 0
    $stuck = 0
    $listed = $false
    if ($spooler.Status -eq 'Running') {
        try {
            $printers = @(Get-Printer -ErrorAction Stop)
            $listed = $true
            foreach ($pr in $printers) {
                $jobs = @()
                try { $jobs = @(Get-PrintJob -PrinterObject $pr -ErrorAction Stop) }
                catch { $lines.Add(("WARN: {0}: jobs not readable ({1})" -f $pr.Name, $_.Exception.Message)); continue }
                if ($jobs.Count -eq 0) { continue }
                $totalJobs += $jobs.Count
                $bad = @($jobs | Where-Object {
                        ([string]$_.JobStatus -match 'Error|Blocked|Offline|PaperOut|UserIntervention|Deleting') -or
                        ($_.SubmittedTime -and $_.SubmittedTime -lt $cutoff)
                    })
                $stuck += $bad.Count
                $oldest = ($jobs | Where-Object { $_.SubmittedTime } | Sort-Object -Property SubmittedTime | Select-Object -First 1)
                $age = ''
                if ($oldest) { $age = ", oldest {0:0} min" -f ((Get-Date) - $oldest.SubmittedTime).TotalMinutes }
                $status = (@($jobs | ForEach-Object { [string]$_.JobStatus } | Where-Object { $_ } | Sort-Object -Unique) -join '/')
                if (-not $status) { $status = 'normal' }
                $lines.Add(("INFO: {0}: {1} job(s), {2} stuck{3}, status {4}" -f $pr.Name, $jobs.Count, $bad.Count, $age, $status))
            }
            $lines.Add(("INFO: {0} printer(s) checked" -f $printers.Count))
        }
        catch { $lines.Add(('WARN: printers not readable: ' + $_.Exception.Message)) }
    }
    else { $lines.Add('INFO: Spooler is not running: jobs cannot be listed') }

    $files = @()
    $filesKnown = $true
    try { $files = Get-SpoolFile }
    catch { $filesKnown = $false; $lines.Add('INFO: spool folder not readable (administrator rights required)') }
    if ($filesKnown) {
        $mb = 0
        foreach ($f in $files) { $mb += $f.Length }
        $lines.Add(("INFO: spool folder: {0} file(s), {1:0.0} MB" -f $files.Count, ($mb / 1MB)))
        # Old spool files with the Spooler stopped also mean a stuck queue
        if (-not $listed) { $stuck += @($files | Where-Object { $_.LastWriteTime -lt $cutoff }).Count }
    }

    $hasWork = ($totalJobs -gt 0) -or ($filesKnown -and $files.Count -gt 0) -or (-not $filesKnown)
    if ($OnlyStuck -and $stuck -eq 0) {
        Write-Report ("OK: no stuck print job (older than {0} min or in error); nothing to do" -f $StuckMinutes) $lines
        $host.SetShouldExit(0); exit 0
    }
    if (-not $hasWork) {
        Write-Report 'OK: print queues are empty; nothing to do' $lines
        $host.SetShouldExit(0); exit 0
    }
    if ($DryRun) {
        Write-Report ("OK: dry run, {0} job(s), {1} stuck; would stop the Spooler, delete the spool files and start it again (pass -DryRun:`$false)" -f $totalJobs, $stuck) $lines
        $host.SetShouldExit(0); exit 0
    }

    # --- Apply --------------------------------------------------------------------------------
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'administrator rights are required to clear the print queue' }

    $deleted = 0
    $left = 0
    $failed = $false
    try {
        if ($spooler.Status -ne 'Stopped') {
            Stop-Service -InputObject $spooler -Force -ErrorAction Stop
            $spooler.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
            $lines.Add('OK: Spooler stopped')
        }
        foreach ($f in (Get-SpoolFile)) {
            try { $f.Delete(); $deleted++ }
            catch { $left++ }
        }
        $lines.Add(("OK: {0} spool file(s) deleted, {1} could not be deleted" -f $deleted, $left))
    }
    catch {
        $failed = $true
        $lines.Add(('FAIL: ' + $_.Exception.Message))
    }
    finally {
        # Always start the Spooler again
        $spooler.Refresh()
        if ($spooler.StartType -eq 'Disabled') { $lines.Add('WARN: Spooler is Disabled, not started') }
        else {
            try {
                if ($spooler.Status -ne 'Running') { Start-Service -InputObject $spooler -ErrorAction Stop }
                $spooler.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
                $lines.Add('OK: Spooler running')
            }
            catch {
                $failed = $true
                $lines.Add(('FAIL: Spooler did not start: ' + $_.Exception.Message))
            }
        }
    }

    if ($failed -or $left -gt 0) {
        $exitCode = 1
        Write-Report ("FAIL: print queue not fully cleared ({0} deleted, {1} left)" -f $deleted, $left) $lines
    }
    else {
        Write-Report ("OK: print queue cleared, {0} spool file(s) deleted" -f $deleted) $lines
    }
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
