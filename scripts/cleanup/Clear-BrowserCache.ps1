#Requires -Version 5.1
<#
.SYNOPSIS
    Reports (dry run) or deletes the disk cache of Chrome, Edge and Firefox for every user.

.DESCRIPTION
    For every user profile on the machine:
      Chrome and Edge, every browser profile (Default, Profile N, ...):
        Cache\Cache_Data, Code Cache and GPUCache
      Firefox, every profile: AppData\Local\Mozilla\Firefox\Profiles\<profile>\cache2
    Only the files inside those folders are removed (and the empty sub folders they leave);
    the cache folders themselves are kept. Cookies, history, passwords, Local Storage, sessions,
    bookmarks and extensions are NEVER touched: every target path is checked to end with one of
    the cache folder names above before anything is deleted, and junctions / symbolic links are
    never followed. Files locked by a running browser are skipped and counted.
    Default is a dry run that reports MB per user and browser. Use it as an action.

.PARAMETER DryRun
    Report what would be freed without deleting anything. Default is $true;
    pass -DryRun:$false to delete.

.EXAMPLE
    (no arguments: dry run)

.EXAMPLE
    -DryRun:$false

.NOTES
    Name:       Cleanup - Browser cache
    GUID:       d2eaeb18-8c81-45a9-a5a9-6d55db66a876
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (unexpected error)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
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
# A folder is cleaned only when its full path ends with one of these
$allowedSuffix = '\Cache\Cache_Data', '\Code Cache', '\GPUCache', '\cache2'

function New-CleanResult {
    return [pscustomobject]@{ Files = 0; Bytes = [int64]0; Locked = 0; Folders = 0 }
}

function Add-CleanResult($Target, $Source) {
    $Target.Files += $Source.Files
    $Target.Bytes += $Source.Bytes
    $Target.Locked += $Source.Locked
    $Target.Folders += $Source.Folders
}

function Test-CacheTarget([string]$Path) {
    foreach ($s in $allowedSuffix) {
        if ($Path.EndsWith($s, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Walks a cache folder without following reparse points; removes (or counts) every file
function Invoke-CacheClean([string]$Path, [bool]$Apply) {
    $r = New-CleanResult
    if (-not (Test-CacheTarget $Path)) { return $r }
    $rootInfo = New-Object System.IO.DirectoryInfo($Path)
    if (-not $rootInfo.Exists -or ($rootInfo.Attributes -band $reparse)) { return $r }
    $r.Folders = 1
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
        # empty sub folders, deepest first; the cache folder itself is kept
        for ($i = $visited.Count - 1; $i -ge 1; $i--) {
            $d = $visited[$i]
            try {
                $d.Refresh()
                if ($d.Exists -and @($d.GetFileSystemInfos()).Count -eq 0) { $d.Delete() }
            }
            catch { Write-Verbose ('folder kept: ' + $d.FullName) }
        }
    }
    return $r
}

# Sub folders of a directory, never links; empty list when unreadable
function Get-SubDirectory([string]$Path) {
    $d = New-Object System.IO.DirectoryInfo($Path)
    if (-not $d.Exists -or ($d.Attributes -band $reparse)) { return @() }
    try { return @($d.GetDirectories() | Where-Object { -not ($_.Attributes -band $reparse) }) }
    catch { return @() }
}

$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    $apply = -not $DryRun
    $total = New-CleanResult
    $userLines = 0
    $userCount = 0
    $skippedUsers = 0
    $chromium = [ordered]@{
        'Chrome' = 'AppData\Local\Google\Chrome\User Data'
        'Edge'   = 'AppData\Local\Microsoft\Edge\User Data'
    }

    foreach ($up in @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=False')) {
        $userDir = [string]$up.LocalPath
        if (-not $userDir) { continue }
        $userDirInfo = New-Object System.IO.DirectoryInfo($userDir)
        if (-not $userDirInfo.Exists -or ($userDirInfo.Attributes -band $reparse)) { continue }
        $userCount++
        $user = Split-Path -Leaf $userDir
        $parts = New-Object System.Collections.Generic.List[string]
        $userTotal = New-CleanResult

        foreach ($browser in $chromium.Keys) {
            $res = New-CleanResult
            $profiles = 0
            foreach ($pd in (Get-SubDirectory (Join-Path $userDir $chromium[$browser]))) {
                $found = $false
                foreach ($sub in 'Cache\Cache_Data', 'Code Cache', 'GPUCache') {
                    $c = Invoke-CacheClean (Join-Path $pd.FullName $sub) $apply
                    if ($c.Folders -gt 0) { $found = $true }
                    Add-CleanResult $res $c
                }
                if ($found) { $profiles++ }
            }
            if ($profiles -gt 0) {
                $parts.Add(("{0} {1:0.0} MB ({2} profile(s))" -f $browser, ($res.Bytes / 1MB), $profiles))
                Add-CleanResult $userTotal $res
            }
        }

        $ff = New-CleanResult
        $ffProfiles = 0
        foreach ($pd in (Get-SubDirectory (Join-Path $userDir 'AppData\Local\Mozilla\Firefox\Profiles'))) {
            $c = Invoke-CacheClean (Join-Path $pd.FullName 'cache2') $apply
            if ($c.Folders -gt 0) { $ffProfiles++ }
            Add-CleanResult $ff $c
        }
        if ($ffProfiles -gt 0) {
            $parts.Add(("Firefox {0:0.0} MB ({1} profile(s))" -f ($ff.Bytes / 1MB), $ffProfiles))
            Add-CleanResult $userTotal $ff
        }

        Add-CleanResult $total $userTotal
        if ($parts.Count -eq 0) { continue }
        if ($userLines -ge 25) { $skippedUsers++; continue }
        $userLines++
        $lock = ''
        if ($userTotal.Locked -gt 0) {
            if ($apply) { $lock = "; {0} locked/unreadable skipped" -f $userTotal.Locked }
            else { $lock = "; {0} folder(s) unreadable, not counted" -f $userTotal.Locked }
        }
        $lines.Add(("INFO: {0}: {1}{2}" -f $user, ($parts -join ', '), $lock))
    }
    if ($skippedUsers -gt 0) { $lines.Add(("INFO: ... {0} more user(s) with browser cache not listed" -f $skippedUsers)) }
    $lines.Add(("INFO: {0} user profile(s) checked" -f $userCount))

    if ($apply) {
        Write-Report ("OK: freed {0:0.0} MB of browser cache in {1} file(s); {2} locked or unreadable item(s) skipped" -f ($total.Bytes / 1MB), $total.Files, $total.Locked) $lines
    }
    else {
        Write-Report ("OK: dry run, {0:0.0} MB of browser cache in {1} file(s) could be freed; run with -DryRun:`$false to delete" -f ($total.Bytes / 1MB), $total.Files) $lines
    }
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
