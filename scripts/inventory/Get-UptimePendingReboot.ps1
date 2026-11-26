#Requires -Version 5.1
<#
.SYNOPSIS
    Reports last boot time, uptime and whether a reboot is pending (and why).

.DESCRIPTION
    Reads Win32_OperatingSystem and the usual pending-reboot markers: Component Based
    Servicing RebootPending, Windows Update RebootRequired, PendingFileRenameOperations,
    a pending computer name change and, when the Configuration Manager client is installed,
    its own reboot flag. Never reboots and changes nothing.
    Use it as a check: exits 2 (warning) when a reboot is pending or uptime is above
    -MaxUptimeDays, otherwise 0. With Fast Startup enabled, a shutdown does not reset uptime.

.PARAMETER MaxUptimeDays
    Uptime in days above which the script warns. Default 30; 0 disables the uptime test.

.EXAMPLE
    -MaxUptimeDays 14

.NOTES
    Name:       Inventory - Uptime and pending reboot
    GUID:       d10f8412-db2d-4051-b27f-977f781c29fa
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (error) | 2 WARN (reboot pending or uptime too long)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxUptimeDays = 30
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

$exitCode = 0
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $boot = [datetime]$os.LastBootUpTime
    $uptime = (Get-Date) - $boot
    $uptimeDays = [math]::Round($uptime.TotalDays, 1)

    $reasons = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('Component Based Servicing (Windows features or updates)')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('Windows Update requires a reboot')
    }
    $sm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    if ($sm -and @($sm.PendingFileRenameOperations | Where-Object { $_ }).Count -gt 0) {
        $reasons.Add('Pending file rename operations')
    }
    $active = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
    $pendingName = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
    if ($active -and $pendingName -and ($active -ne $pendingName)) {
        $reasons.Add('Computer name change')
    }
    try {
        $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($ccm -and ($ccm.RebootPending -or $ccm.IsHardRebootPending)) {
            $reasons.Add('Configuration Manager client')
        }
    }
    catch {
        Write-Verbose 'Configuration Manager client not present'
    }

    $tooLong = ($MaxUptimeDays -gt 0 -and $uptime.TotalDays -gt $MaxUptimeDays)
    if ($reasons.Count -gt 0 -and $tooLong) {
        Write-Output ("WARN: reboot pending ({0} reason(s)) and uptime {1} day(s) is above {2}" -f $reasons.Count, $uptimeDays, $MaxUptimeDays)
        $exitCode = 2
    }
    elseif ($reasons.Count -gt 0) {
        Write-Output ("WARN: reboot pending ({0} reason(s)); uptime {1} day(s)" -f $reasons.Count, $uptimeDays)
        $exitCode = 2
    }
    elseif ($tooLong) {
        Write-Output ("WARN: uptime {0} day(s) is above {1}; no reboot pending" -f $uptimeDays, $MaxUptimeDays)
        $exitCode = 2
    }
    else {
        Write-Output ("OK: no reboot pending; uptime {0} day(s)" -f $uptimeDays)
    }

    Write-Output ("INFO: Last boot: {0}" -f $boot.ToString('yyyy-MM-dd HH:mm'))
    foreach ($r in $reasons) { Write-Output ("INFO: Pending reboot reason: {0}" -f $r) }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
