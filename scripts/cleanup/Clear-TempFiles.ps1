#Requires -Version 5.1
<#
.SYNOPSIS
    Reports (dry run) or deletes old temporary files to free disk space.

.DESCRIPTION
    Locations: Windows\Temp, AppData\Local\Temp of every user profile,
    SoftwareDistribution\Download (skipped while Windows Update is installing),
    the Windows Error Reporting queues and, with -IncludeRecycleBin, the recycle bin of every
    fixed drive. Only files last written more than -OlderThanDays days ago are considered;
    empty sub folders older than that are removed after their files.
    Never touches Downloads, Documents, Desktop or any other user folder, never follows
    junctions or symbolic links, never stops a service. Locked / in-use files are skipped.
    Default is a dry run that only reports how many files and MB each location would free.
    Use it as an action or a scheduled task; it exits 0, or 1 only on an unexpected error.

.PARAMETER OlderThanDays
    Minimum age in days (last write time) of a file to be removed. Default 7.

.PARAMETER IncludeRecycleBin
    Also empty recycle bin items deleted more than -OlderThanDays days ago. Default off.

.PARAMETER DryRun
    Report what would be freed without deleting anything. Default is $true;
    pass -DryRun:$false to delete.

.EXAMPLE
    -OlderThanDays 7

.EXAMPLE
    -OlderThanDays 14 -IncludeRecycleBin -DryRun:$false

.NOTES
    Name:       Cleanup - Clear temporary files
    GUID:       66133397-fe41-4c4a-ace0-274313e4db1b
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (unexpected error)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$OlderThanDays = 7,
    [switch]$IncludeRecycleBin,
    [switch]$DryRun = $true
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

$reparse = [System.IO.FileAttributes]::ReparsePoint
$selfPath = [string]$PSCommandPath

function New-CleanResult {
    return [pscustomobject]@{ Files = 0; Bytes = [int64]0; Locked = 0 }
}

function Add-CleanResult($Target, $Source) {
    $Target.Files += $Source.Files
    $Target.Bytes += $Source.Bytes
    $Target.Locked += $Source.Locked
}

# Walks a folder without following reparse points and removes (or counts) files older than $Cutoff.
function Invoke-FolderClean([string]$Path, [datetime]$Cutoff, [bool]$RemoveRoot, [bool]$Apply) {
    $r = New-CleanResult
    $rootInfo = New-Object System.IO.DirectoryInfo($Path)
    if (-not $rootInfo.Exists) { return $r }
    if ($rootInfo.Attributes -band $reparse) { return $r }

    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $visited = New-Object System.Collections.Generic.List[System.IO.DirectoryInfo]
    $stack.Push($rootInfo)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $visited.Add($dir)
        $entries = $null
        try { $entries = $dir.GetFileSystemInfos() }
        catch { $r.Locked++; continue }
        foreach ($e in $entries) {
            if ($e.Attributes -band $reparse) { continue }
            if ($e -is [System.IO.DirectoryInfo]) { $stack.Push($e); continue }
            if ($e.LastWriteTime -gt $Cutoff) { continue }
            if ($selfPath -and ($e.FullName -eq $selfPath)) { continue }
            $len = [int64]$e.Length
            if ($Apply) {
                try {
                    if ($e.IsReadOnly) { $e.IsReadOnly = $false }
                    $e.Delete()
                    $r.Files++
                    $r.Bytes += $len
                }
                catch { $r.Locked++ }
            }
            else {
                $r.Files++
                $r.Bytes += $len
            }
        }
    }

    if ($Apply) {
        # Deepest folders first; only empty folders, created before the cutoff, never links
        for ($i = $visited.Count - 1; $i -ge 0; $i--) {
            $d = $visited[$i]
            $isRoot = ($i -eq 0)
            if ($isRoot -and -not $RemoveRoot) { continue }
            try {
                $d.Refresh()
                if (-not $d.Exists) { continue }
                if (-not $isRoot -and $d.CreationTime -gt $Cutoff) { continue }
                if (@($d.GetFileSystemInfos()).Count -eq 0) { $d.Delete() }
            }
            catch { Write-Verbose ("Folder kept: " + $d.FullName) }
        }
    }
    return $r
}

function Format-MB([int64]$Bytes) {
    return ('{0:0.0}' -f ($Bytes / 1MB))
}

$exitCode = 0
try {
    if ($OlderThanDays -lt 0) { $OlderThanDays = 0 }
    $apply = -not $DryRun
    $cutoff = (Get-Date).AddDays(-$OlderThanDays)
    $lines = New-Object System.Collections.Generic.List[string]
    $total = New-CleanResult

    function Add-LocationLine([string]$Label, $Res) {
        if ($apply) {
            $lines.Add(("INFO: {0}: freed {1} MB in {2} file(s), {3} locked or unreadable skipped" -f $Label, (Format-MB $Res.Bytes), $Res.Files, $Res.Locked))
        }
        else {
            $note = ''
            if ($Res.Locked -gt 0) { $note = " ({0} folder(s) unreadable, not counted)" -f $Res.Locked }
            $lines.Add(("INFO: {0}: {1} file(s), {2} MB would be freed{3}" -f $Label, $Res.Files, (Format-MB $Res.Bytes), $note))
        }
        Add-CleanResult $total $Res
    }

    # 1. Windows\Temp
    $winTemp = Join-Path $env:windir 'Temp'
    Add-LocationLine 'Windows temp' (Invoke-FolderClean $winTemp $cutoff $false $apply)

    # 2. AppData\Local\Temp of every (non special) user profile
    $userRes = New-CleanResult
    $profileCount = 0
    foreach ($prof in @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=False')) {
        $local = [string]$prof.LocalPath
        if (-not $local) { continue }
        $tmp = Join-Path $local 'AppData\Local\Temp'
        if (-not $tmp.EndsWith('\AppData\Local\Temp', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not (Test-Path -LiteralPath $tmp -PathType Container)) { continue }
        $profileCount++
        Add-CleanResult $userRes (Invoke-FolderClean $tmp $cutoff $false $apply)
    }
    Add-LocationLine ("User temp ({0} profile(s))" -f $profileCount) $userRes

    # 3. Windows Update download cache, only when no update is being installed
    $wuDownload = Join-Path $env:windir 'SoftwareDistribution\Download'
    $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    $installing = ($wu -and $wu.Status -eq 'Running' -and @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue).Count -gt 0)
    if ($installing) {
        $lines.Add("INFO: Windows Update download cache: skipped, Windows Update is installing")
    }
    else {
        Add-LocationLine 'Windows Update download cache' (Invoke-FolderClean $wuDownload $cutoff $false $apply)
    }

    # 4. Windows Error Reporting queues
    $werRes = New-CleanResult
    foreach ($sub in 'ReportQueue', 'ReportArchive', 'Temp') {
        $p = Join-Path $env:ProgramData ('Microsoft\Windows\WER\' + $sub)
        Add-CleanResult $werRes (Invoke-FolderClean $p $cutoff $false $apply)
    }
    Add-LocationLine 'Windows Error Reporting' $werRes

    # 5. Recycle bin (optional). $I<id> holds the deletion time, $R<id> the deleted item.
    if ($IncludeRecycleBin) {
        $binRes = New-CleanResult
        foreach ($ld in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
            $bin = New-Object System.IO.DirectoryInfo(([string]$ld.DeviceID) + '\$Recycle.Bin')
            if (-not $bin.Exists -or ($bin.Attributes -band $reparse)) { continue }
            $sidDirs = @()
            try { $sidDirs = @($bin.GetDirectories()) } catch { $binRes.Locked++ }
            foreach ($sidDir in $sidDirs) {
                if ($sidDir.Attributes -band $reparse) { continue }
                $infos = @()
                try { $infos = @($sidDir.GetFiles('$I*')) } catch { $binRes.Locked++; continue }
                foreach ($info in $infos) {
                    if ($info.LastWriteTime -gt $cutoff) { continue }
                    $rPath = Join-Path $sidDir.FullName ('$R' + $info.Name.Substring(2))
                    $rFile = New-Object System.IO.FileInfo($rPath)
                    $rDir = New-Object System.IO.DirectoryInfo($rPath)
                    $ok = $true
                    if ($rFile.Exists -and -not ($rFile.Attributes -band $reparse)) {
                        $len = [int64]$rFile.Length
                        if ($apply) {
                            try { if ($rFile.IsReadOnly) { $rFile.IsReadOnly = $false }; $rFile.Delete() }
                            catch { $ok = $false; $binRes.Locked++ }
                        }
                        if ($ok) { $binRes.Files++; $binRes.Bytes += $len }
                    }
                    elseif ($rDir.Exists -and -not ($rDir.Attributes -band $reparse)) {
                        $sub = Invoke-FolderClean $rDir.FullName ([datetime]::MaxValue) $true $apply
                        Add-CleanResult $binRes $sub
                        if ($sub.Locked -gt 0) { $ok = $false }
                    }
                    if ($apply -and $ok) {
                        try { $info.Delete() } catch { $binRes.Locked++ }
                    }
                }
            }
        }
        Add-LocationLine 'Recycle bin' $binRes
    }

    if ($apply) {
        Write-Output ("OK: freed {0} MB in {1} file(s) older than {2} day(s); {3} locked or unreadable item(s) skipped" -f (Format-MB $total.Bytes), $total.Files, $OlderThanDays, $total.Locked)
    }
    else {
        Write-Output ("OK: dry run, {0} MB in {1} file(s) older than {2} day(s) could be freed; run with -DryRun:`$false to delete" -f (Format-MB $total.Bytes), $total.Files, $OlderThanDays)
    }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
