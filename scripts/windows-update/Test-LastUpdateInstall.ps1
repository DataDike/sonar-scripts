#Requires -Version 5.1
<#
.SYNOPSIS
    Checks how many days ago an update was last installed successfully.

.DESCRIPTION
    Read-only check. It reads the Windows Update Agent install history (Microsoft.Update.Session,
    QueryHistory) and the installed hotfix list (Get-HotFix InstalledOn), and uses the newest
    successful install date found in either source. Antivirus definition / security intelligence
    updates are ignored by default, because they install every day and would hide missing
    operating system updates.

    Verdict rules (age = days since the newest install):
      FAIL (1) age greater than -MaxDays, no install found, or the check failed.
      WARN (2) age greater than 75% of -MaxDays.
      OK   (0) otherwise.

    With -IncludePending the script also searches for updates that are not installed and not
    hidden (software only). The search contacts the configured update source and can take several
    minutes: the manifest default timeout is 600 seconds. Pending updates are reported as INFO and
    do not change the exit code.

.PARAMETER MaxDays
    Maximum age, in days, of the newest install before FAIL. Default 35.

.PARAMETER IncludePending
    Also count pending software updates (slow; triggers an update search).

.PARAMETER IncludeDefinitionUpdates
    Count antivirus definition / security intelligence updates as installs.

.EXAMPLE
    -MaxDays 35 -IncludePending

.NOTES
    Name:       Windows Update - Last install age
    GUID:       653da36b-2611-4d3b-8181-68373b3e02bb
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); history also readable as a standard user
    Exit codes: 0 OK | 1 FAIL | 2 WARN
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxDays = 35,
    [switch]$IncludePending,
    [switch]$IncludeDefinitionUpdates
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$definitionPattern = 'Security Intelligence Update|Definition Update|KB2267602|KB2461484|KB915597|KB4052623'
$lines = New-Object System.Collections.Generic.List[string]

function Get-ShortText([string]$text, [int]$max) {
    if ($null -eq $text) { return '' }
    $t = ($text -replace '[^\x20-\x7E]', '?').Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }
    return $t
}

$exitCode = 0
try {
    if ($MaxDays -lt 1) { throw 'MaxDays must be 1 or more' }
    $newest = $null; $newestTitle = ''; $newestSource = ''

    # 1. Windows Update Agent history (dates are UTC)
    $session = $null
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $history = $searcher.QueryHistory(0, [math]::Min($total, 500))
            $ok = 0; $future = 0
            $futureLimit = [datetime]::UtcNow.AddDays(1)
            foreach ($h in $history) {
                # Operation 1 = installation; ResultCode 2 = succeeded, 3 = succeeded with errors
                if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
                if (-not $IncludeDefinitionUpdates -and ([string]$h.Title -match $definitionPattern)) { continue }
                $d = [datetime]$h.Date
                # a date in the future comes from a corrupted entry or a wrong clock: ignore it
                if ($d -gt $futureLimit) { $future++; continue }
                $ok++
                if ($null -eq $newest -or $d -gt $newest) { $newest = $d; $newestTitle = [string]$h.Title; $newestSource = 'update history' }
            }
            $lines.Add(("INFO: update history: {0} entries read, {1} successful installs counted" -f [math]::Min($total, 500), $ok))
            if ($future -gt 0) { $lines.Add(("INFO: {0} history entries dated in the future were ignored" -f $future)) }
        } else {
            $lines.Add('INFO: update history is empty')
        }
    } catch {
        $lines.Add('INFO: update history unavailable: ' + (Get-ShortText $_.Exception.Message 150))
    }

    # 2. Installed hotfixes (InstalledOn is a local date without time)
    try {
        $hf = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn -and $_.InstalledOn -le (Get-Date).AddDays(1) })
        if ($hf.Count -gt 0) {
            $top = $hf | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
            $d = ([datetime]$top.InstalledOn).ToUniversalTime()
            if ($null -eq $newest -or $d -gt $newest) { $newest = $d; $newestTitle = [string]$top.HotFixID; $newestSource = 'hotfix list' }
            $lines.Add(("INFO: hotfix list: {0} entries with a date, newest {1} ({2})" -f $hf.Count, ([datetime]$top.InstalledOn).ToString('yyyy-MM-dd'), $top.HotFixID))
        } else {
            $lines.Add('INFO: hotfix list has no dated entries')
        }
    } catch {
        $lines.Add('INFO: hotfix list unavailable: ' + (Get-ShortText $_.Exception.Message 150))
    }

    # 3. Pending updates (optional, slow)
    if ($IncludePending) {
        try {
            if ($null -eq $session) { $session = New-Object -ComObject 'Microsoft.Update.Session' }
            $s = $session.CreateUpdateSearcher()
            $result = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            $pending = @($result.Updates)
            $security = @($pending | Where-Object { $_.MsrcSeverity }).Count
            $lines.Add(("INFO: pending software updates: {0} ({1} with a security severity)" -f $pending.Count, $security))
            $pending | Select-Object -First 5 | ForEach-Object {
                $lines.Add('INFO:   pending: ' + (Get-ShortText ([string]$_.Title) 110))
            }
        } catch {
            $lines.Add('INFO: pending update search failed: ' + (Get-ShortText $_.Exception.Message 150))
        }
    }

    if ($null -eq $newest) {
        $exitCode = 1
        Write-Output 'FAIL: no successful update install found in history or hotfix list'
    } else {
        $age = [math]::Floor(([datetime]::UtcNow - $newest).TotalDays)
        if ($age -lt 0) { $age = 0 }
        $detail = "last update install {0} days ago ({1}, {2} via {3}); limit {4} days" -f $age, $newest.ToString('yyyy-MM-dd'), (Get-ShortText $newestTitle 90), $newestSource, $MaxDays
        if ($age -gt $MaxDays) { $exitCode = 1; Write-Output ('FAIL: ' + $detail) }
        elseif ($age -gt ($MaxDays * 0.75)) { $exitCode = 2; Write-Output ('WARN: ' + $detail) }
        else { Write-Output ('OK: ' + $detail) }
    }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
