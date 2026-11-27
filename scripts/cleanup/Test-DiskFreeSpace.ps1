#Requires -Version 5.1
<#
.SYNOPSIS
    Checks free space on local fixed drives against a percent and a GB threshold.

.DESCRIPTION
    Reads Win32_LogicalDisk (DriveType 3 = local fixed disk with a drive letter). Changes nothing.
    For each drive:
      FAIL when free percent is below -MinFreePercent AND free GB is below -MinFreeGB
           (both limits broken: really out of space, on small and on large disks);
      WARN when only one of the two limits is broken;
      OK   otherwise.
    The worst drive sets the result. Use it as a check: 0 OK, 2 warning, 1 failing,
    3 when the drive given in -Drive does not exist.

.PARAMETER Drive
    Optional drive letter to check (for example 'C' or 'C:'). Default: every fixed drive.

.PARAMETER MinFreePercent
    Minimum free space in percent of the drive size. Default 10.

.PARAMETER MinFreeGB
    Minimum free space in GB. Default 10.

.EXAMPLE
    -MinFreePercent 10 -MinFreeGB 10

.EXAMPLE
    -Drive C -MinFreePercent 15 -MinFreeGB 20

.NOTES
    Name:       Cleanup - Disk free space
    GUID:       64a7ad23-b2b6-4a10-8ba4-c48226efc786
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (both limits broken, or error) | 2 WARN (one limit broken) | 3 NOT APPLICABLE (drive not found)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string]$Drive = '',
    [int]$MinFreePercent = 10,
    [int]$MinFreeGB = 10
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

$exitCode = 0
try {
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { [double]$_.Size -gt 0 })
    $letter = ($Drive -replace '[:\\\s]', '').ToUpper()
    if ($letter) {
        if ($letter -notmatch '^[A-Z]$') {
            Write-Output ("FAIL: invalid -Drive value; use a single letter such as C")
            $host.SetShouldExit(1); exit 1
        }
        $disks = @($disks | Where-Object { ([string]$_.DeviceID).ToUpper() -eq ($letter + ':') })
        if ($disks.Count -eq 0) {
            Write-Output ("INFO: drive {0}: is not a local fixed drive on this machine" -f $letter)
            $host.SetShouldExit(3); exit 3
        }
    }
    if ($disks.Count -eq 0) {
        Write-Output "INFO: no local fixed drive with a drive letter found"
        $host.SetShouldExit(3); exit 3
    }

    $fails = 0; $warns = 0
    $details = New-Object System.Collections.Generic.List[string]
    foreach ($d in ($disks | Sort-Object -Property DeviceID)) {
        $size = [double]$d.Size
        $free = [double]$d.FreeSpace
        $pct = [math]::Round(100 * $free / $size, 1)
        $gb = [math]::Round($free / 1GB, 2)
        $lowPct = ($pct -lt $MinFreePercent)
        $lowGb = ($gb -lt $MinFreeGB)
        $state = 'OK'
        if ($lowPct -and $lowGb) { $state = 'FAIL'; $fails++ }
        elseif ($lowPct -or $lowGb) { $state = 'WARN'; $warns++ }
        $details.Add(("{0}: {1} {2} GB free of {3} GB ({4}%)" -f $state, $d.DeviceID, $gb, [math]::Round($size / 1GB, 2), $pct))
    }

    $limits = "limits {0}% and {1} GB" -f $MinFreePercent, $MinFreeGB
    if ($fails -gt 0) {
        Write-Output ("FAIL: {0} drive(s) below both {1}" -f $fails, $limits)
        $exitCode = 1
    }
    elseif ($warns -gt 0) {
        Write-Output ("WARN: {0} drive(s) below one of the {1}" -f $warns, $limits)
        $exitCode = 2
    }
    else {
        Write-Output ("OK: {0} drive(s) above the {1}" -f $disks.Count, $limits)
    }
    $details | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
