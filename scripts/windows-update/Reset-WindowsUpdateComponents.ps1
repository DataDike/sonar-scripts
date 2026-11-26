#Requires -Version 5.1
<#
.SYNOPSIS
    Resets the Windows Update client cache (classic component reset).

.DESCRIPTION
    Action script. Steps, in order:
      1. stop the services wuauserv, bits, cryptsvc and msiserver;
      2. rename %SystemRoot%\SoftwareDistribution and %SystemRoot%\System32\catroot2 to
         <name>.bak-<yyyyMMddHHmmss> (Windows recreates both folders);
      3. start the four services again - this always runs (finally block), even when a step fails;
      4. remove older <name>.bak-<14 digits> folders, keeping only the newest backup.
    It does not reset Winsock, proxy settings, BITS jobs or policies, and never reboots.
    The update history shown in Settings is rebuilt from the next scan.

    By default it runs in dry run: it prints the plan and changes nothing.
    Pass -DryRun:$false to apply. Requires administrator / SYSTEM to apply.
    Running it twice is harmless: each run creates a fresh cache and keeps one backup.

    Exit codes: 0 done (or dry run), 1 a step failed or a service did not start again,
    2 reset done but an old backup could not be removed.

.PARAMETER DryRun
    Report what would change without changing anything. Default is $true; pass -DryRun:$false to apply.

.PARAMETER ServiceTimeoutSeconds
    Seconds to wait for each service to stop or start. Default 60.

.EXAMPLE
    -DryRun:$false

.NOTES
    Name:       Windows Update - Reset components
    GUID:       6ceb6461-4a64-4df2-b845-43a263abfbd3
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL | 2 WARN
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$DryRun = $true,
    [int]$ServiceTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$serviceNames = 'wuauserv', 'bits', 'cryptsvc', 'msiserver'
$folders = @(
    (Join-Path $env:SystemRoot 'SoftwareDistribution'),
    (Join-Path $env:SystemRoot 'System32\catroot2')
)
$stamp = (Get-Date).ToString('yyyyMMddHHmmss')
$lines = New-Object System.Collections.Generic.List[string]
$script:isFail = $false
$script:isWarn = $false
function Add-Fail([string]$msg) { $script:isFail = $true; $lines.Add('FAIL: ' + $msg) }
function Add-Warn([string]$msg) { $script:isWarn = $true; $lines.Add('WARN: ' + $msg) }
function Add-Ok([string]$msg) { $lines.Add('OK: ' + $msg) }
function Add-Info([string]$msg) { $lines.Add('INFO: ' + $msg) }

function Get-OldBackup([string]$folder) {
    $parent = Split-Path -Parent $folder
    $leaf = Split-Path -Leaf $folder
    $rx = '^' + [regex]::Escape($leaf) + '\.bak-\d{14}$'
    @(Get-ChildItem -LiteralPath $parent -Directory -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $rx } | Sort-Object -Property Name -Descending)
}

function Wait-ServiceState($svc, [string]$state) {
    try {
        $svc.WaitForStatus($state, [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
        return $true
    } catch { return $false }
}

$exitCode = 0
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

try {
    if ($DryRun) {
        Add-Info 'dry run: nothing is changed; pass -DryRun:$false to apply'
        if (-not $isAdmin) { Add-Info 'not running as administrator: applying would fail' }
        foreach ($n in $serviceNames) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($s) { Add-Info ("would stop and start service {0} (now {1}, start {2})" -f $n, $s.Status, $s.StartType) }
            else { Add-Info "service $n not found (would be skipped)" }
        }
        foreach ($f in $folders) {
            if (Test-Path -LiteralPath $f) { Add-Info ("would rename {0} to {1}.bak-{2}" -f $f, (Split-Path -Leaf $f), $stamp) }
            else { Add-Info "folder $f not found (would be skipped)" }
            $old = Get-OldBackup $f
            foreach ($o in $old) { Add-Info ("would remove old backup {0}" -f $o.Name) }
        }
        Write-Output 'OK: dry run completed, no changes made'
        $lines | ForEach-Object { Write-Output $_ }
        exit 0
    }

    if (-not $isAdmin) { throw 'administrator rights are required to reset Windows Update components' }

    $renamed = New-Object System.Collections.Generic.List[string]
    try {
        # 1. stop services
        foreach ($n in $serviceNames) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if (-not $s) { Add-Info "service $n not found, skipped"; continue }
            if ($s.Status -eq 'Stopped') { Add-Info "service $n already stopped"; continue }
            Stop-Service -InputObject $s -Force -NoWait -ErrorAction Stop
            if (Wait-ServiceState $s 'Stopped') { Add-Ok "service $n stopped" }
            else { throw "service $n did not stop within $ServiceTimeoutSeconds seconds" }
        }

        # 2. rename folders
        foreach ($f in $folders) {
            if (-not (Test-Path -LiteralPath $f)) { Add-Info "folder $f not found, skipped"; continue }
            $newName = (Split-Path -Leaf $f) + '.bak-' + $stamp
            $attempt = 0
            while ($true) {
                try {
                    Rename-Item -LiteralPath $f -NewName $newName -ErrorAction Stop
                    break
                } catch {
                    # a service may have been restarted by a trigger: stop it again and retry once
                    $attempt++
                    if ($attempt -ge 2) { throw ("cannot rename {0}: {1}" -f $f, $_.Exception.Message) }
                    foreach ($n in $serviceNames) {
                        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
                        if ($s -and $s.Status -ne 'Stopped') { Stop-Service -InputObject $s -Force -ErrorAction SilentlyContinue }
                    }
                    Start-Sleep -Seconds 3
                }
            }
            $renamed.Add($f)
            Add-Ok ("renamed {0} to {1}" -f $f, $newName)
        }
    }
    catch {
        Add-Fail $_.Exception.Message
    }
    finally {
        # 3. always start the services again
        foreach ($n in $serviceNames) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if (-not $s) { continue }
            if ($s.StartType -eq 'Disabled') { Add-Warn "service $n is Disabled, not started"; continue }
            try {
                $s.Refresh()
                if ($s.Status -ne 'Running') { Start-Service -InputObject $s -ErrorAction Stop }
                if (Wait-ServiceState $s 'Running') { Add-Ok "service $n running" }
                else { Add-Fail "service $n did not start within $ServiceTimeoutSeconds seconds" }
            } catch {
                Add-Fail ("service {0} failed to start: {1}" -f $n, $_.Exception.Message)
            }
        }
    }

    # 4. keep only the newest backup (only folders renamed by this script's naming pattern)
    foreach ($f in $renamed) {
        $old = @(Get-OldBackup $f | Select-Object -Skip 1)
        foreach ($o in $old) {
            try {
                Remove-Item -LiteralPath $o.FullName -Recurse -Force -ErrorAction Stop
                Add-Ok ("removed old backup {0}" -f $o.Name)
            } catch {
                Add-Warn ("could not remove old backup {0}: {1}" -f $o.Name, $_.Exception.Message)
            }
        }
    }

    if ($script:isFail) { $exitCode = 1; Write-Output 'FAIL: Windows Update reset did not complete' }
    elseif ($script:isWarn) { $exitCode = 2; Write-Output 'WARN: Windows Update reset done with warnings' }
    else { Write-Output 'OK: Windows Update components reset; run an update scan to rebuild the cache' }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $lines | ForEach-Object { Write-Output $_ }
    $exitCode = 1
}
exit $exitCode
