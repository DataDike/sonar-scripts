#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the health of every physical disk: status, temperature, wear and uncorrected errors.

.DESCRIPTION
    Reads the physical disks with Get-PhysicalDisk (name, media type, bus type, size, health
    status and operational status) and, where the disk and driver expose them, the reliability
    counters with Get-StorageReliabilityCounter (temperature, wear, uncorrected read/write errors,
    power-on hours). Reliability counters need administrator rights; without them the disk status
    is still reported. When the Storage module cannot be used, it falls back to Win32_DiskDrive
    (status only, which still shows a SMART "Pred Fail").
    Result: FAIL when a disk is Unhealthy, reports a SMART predicted failure or has uncorrected
    errors; WARN when a disk is in Warning state or temperature/wear are over the limits;
    NOT APPLICABLE when no physical disk information is available (some virtual machines).
    Read-only; use it as a script check.

.PARAMETER MaxTemperature
    Highest accepted disk temperature in degrees Celsius. Default 60.

.PARAMETER MaxWear
    Highest accepted wear percentage (SSD life used, 0-100). Default 80.

.EXAMPLE
    -MaxTemperature 55 -MaxWear 70

.NOTES
    Name:       Hardware - Disk health
    GUID:       4e184bbf-08e1-414e-8999-69891fbd30fd
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); without admin rights only the disk status is read
    Exit codes: 0 OK | 1 FAIL (unhealthy disk, uncorrected errors, or error) | 2 WARN | 3 NOT APPLICABLE (no physical disk info)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxTemperature = 60,
    [int]$MaxWear = 80
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output must stay ASCII: Windows returns localized text (accents are stripped).
function ConvertTo-AsciiText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return ([regex]::Replace($n, '[^\x20-\x7E]', '')).Trim()
}

# Prints the verdict, then the detail lines inside a 4 KB budget, then the footer lines.
function Write-Report([string]$Verdict, [object[]]$Lines, [object[]]$Footer) {
    $v = ConvertTo-AsciiText $Verdict
    Write-Output $v
    $foot = @($Footer | Where-Object { $_ } | ForEach-Object { ConvertTo-AsciiText ([string]$_) })
    $used = $v.Length + 2 + 60
    foreach ($f in $foot) { $used += $f.Length + 2 }
    $all = @($Lines | Where-Object { $_ })
    for ($i = 0; $i -lt $all.Count; $i++) {
        $l = ConvertTo-AsciiText ([string]$all[$i])
        if (($used + $l.Length + 2) -gt 3900) { Write-Output ('INFO: {0} more not shown' -f ($all.Count - $i)); break }
        Write-Output $l
        $used += $l.Length + 2
    }
    foreach ($f in $foot) { Write-Output $f }
}

function Test-AccessDenied($ErrorRecord) {
    $m = [string]$ErrorRecord.Exception.Message
    return ([string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        $ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or
        $m -match '(?i)access.*denied|0x80070005')
}

function Format-Size($Bytes) {
    if (-not $Bytes) { return '?' }
    $gb = [double]$Bytes / 1GB
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($gb -ge 1000) { return [string]::Format($inv, '{0:0.0} TB', ($gb / 1024)) }
    return [string]::Format($inv, '{0:0} GB', $gb)
}

$exitCode = 0
try {
    if ($MaxTemperature -lt 1) { $MaxTemperature = 60 }
    if ($MaxWear -lt 1 -or $MaxWear -gt 100) { $MaxWear = 80 }

    $fails = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]
    $footer = New-Object System.Collections.Generic.List[string]

    $disks = @()
    $storageError = $null
    try {
        if (-not (Get-Command -Name Get-PhysicalDisk -ErrorAction SilentlyContinue)) { throw 'Get-PhysicalDisk not available' }
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object -Property DeviceId)
    }
    catch {
        $storageError = if (Test-AccessDenied $_) { 'access denied' } else { ConvertTo-AsciiText $_.Exception.Message }
    }

    if ($disks.Count) {
        $counterDenied = 0
        $counterMissing = 0
        foreach ($d in $disks) {
            $name = ConvertTo-AsciiText ([string]$d.FriendlyName)
            if (-not $name) { $name = 'Disk ' + [string]$d.DeviceId }
            $health = [string]$d.HealthStatus
            $op = (@($d.OperationalStatus) | ForEach-Object { [string]$_ }) -join ','
            $info = '{0} | {1} | {2} | {3} | health {4} | {5}' -f $name, [string]$d.MediaType, [string]$d.BusType, (Format-Size $d.Size), $health, $op

            if ($health -eq 'Unhealthy') { $fails.Add($name + ' is Unhealthy (' + $op + ')') | Out-Null }
            elseif ($health -eq 'Warning') { $warns.Add($name + ' health is Warning (' + $op + ')') | Out-Null }

            $rc = $null
            try { $rc = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction Stop }
            catch {
                if (Test-AccessDenied $_) { $counterDenied++ } else { $counterMissing++ }
            }
            if ($rc) {
                $parts = New-Object System.Collections.Generic.List[string]
                $temp = $rc.Temperature
                if ($null -ne $temp -and [int]$temp -gt 0) {
                    $parts.Add(('temp {0}C' -f $temp)) | Out-Null
                    if ([int]$temp -gt $MaxTemperature) { $warns.Add(('{0} temperature {1}C over {2}C' -f $name, $temp, $MaxTemperature)) | Out-Null }
                }
                $wear = $rc.Wear
                if ($null -ne $wear -and [string]$d.MediaType -ne 'HDD') {
                    $parts.Add(('wear {0}%' -f $wear)) | Out-Null
                    if ([int]$wear -gt $MaxWear) { $warns.Add(('{0} wear {1}% over {2}%' -f $name, $wear, $MaxWear)) | Out-Null }
                }
                $re = $rc.ReadErrorsUncorrected
                $we = $rc.WriteErrorsUncorrected
                if ($null -ne $re) { $parts.Add(('read err {0}' -f $re)) | Out-Null }
                if ($null -ne $we) { $parts.Add(('write err {0}' -f $we)) | Out-Null }
                $bad = 0
                if ($null -ne $re) { $bad += [long]$re }
                if ($null -ne $we) { $bad += [long]$we }
                if ($bad -gt 0) { $fails.Add(('{0} has {1} uncorrected error(s)' -f $name, $bad)) | Out-Null }
                if ($null -ne $rc.PowerOnHours) { $parts.Add(('{0} h on' -f $rc.PowerOnHours)) | Out-Null }
                if ($parts.Count) { $info += ' | ' + ($parts -join ', ') } else { $info += ' | no counters reported' }
            }
            $lines.Add('INFO: ' + $info) | Out-Null
        }
        if ($counterDenied) { $footer.Add(('INFO: reliability counters: access denied on {0} disk(s) (run as SYSTEM or administrator)' -f $counterDenied)) | Out-Null }
        if ($counterMissing) { $footer.Add(('INFO: reliability counters not available on {0} disk(s)' -f $counterMissing)) | Out-Null }
        $footer.Add('INFO: read with Get-PhysicalDisk') | Out-Null
    }
    else {
        # Fallback: Win32_DiskDrive status (SMART "Pred Fail" shows here)
        $drives = @()
        try { $drives = @(Get-CimInstance -ClassName Win32_DiskDrive -Property Model, Status, Size, InterfaceType, Index -ErrorAction Stop | Sort-Object -Property Index) }
        catch {
            $why = if (Test-AccessDenied $_) { 'access denied' } else { ConvertTo-AsciiText $_.Exception.Message }
            if (-not $storageError) { $storageError = $why } else { $storageError += '; Win32_DiskDrive: ' + $why }
        }
        if (-not $drives.Count) {
            if ($storageError -eq 'access denied') {
                Write-Report 'FAIL: access denied reading physical disks (run as SYSTEM or administrator)' @() @()
                $host.SetShouldExit(1); exit 1
            }
            $why = if ($storageError) { ' (' + $storageError + ')' } else { '' }
            Write-Report ('INFO: no physical disk information available' + $why) @() @()
            $host.SetShouldExit(3); exit 3
        }
        foreach ($dr in $drives) {
            $name = ConvertTo-AsciiText ([string]$dr.Model)
            $status = [string]$dr.Status
            if ($status -eq 'Pred Fail') { $fails.Add($name + ' reports a SMART predicted failure') | Out-Null }
            elseif ($status -and $status -ne 'OK') { $warns.Add($name + ' status ' + $status) | Out-Null }
            $lines.Add(('INFO: {0} | {1} | {2} | status {3}' -f $name, [string]$dr.InterfaceType, (Format-Size $dr.Size), $status)) | Out-Null
        }
        $why = if ($storageError) { ' (Get-PhysicalDisk: ' + $storageError + ')' } else { '' }
        $footer.Add('INFO: read with Win32_DiskDrive, status only' + $why) | Out-Null
        $disks = $drives
    }

    if ($fails.Count) {
        $verdict = 'FAIL: ' + ($fails -join '; ')
        $exitCode = 1
    }
    elseif ($warns.Count) {
        $verdict = 'WARN: ' + ($warns -join '; ')
        $exitCode = 2
    }
    else {
        $verdict = 'OK: {0} disk(s) healthy (limits {1}C, wear {2}%)' -f $disks.Count, $MaxTemperature, $MaxWear
    }
    if ($verdict.Length -gt 600) { $verdict = $verdict.Substring(0, 597) + '...' }
    Write-Report $verdict $lines $footer
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading disk health (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not read disk health: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
