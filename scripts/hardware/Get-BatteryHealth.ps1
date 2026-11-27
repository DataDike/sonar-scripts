#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the wear of every laptop battery (full charge capacity against design capacity).

.DESCRIPTION
    Reads the batteries from WMI only, no report files: designed capacity (root\wmi
    BatteryStaticData), full charged capacity (BatteryFullChargedCapacity), cycle count
    (BatteryCycleCount, when the firmware reports it) and status and charge from Win32_Battery.
    Wear % = 1 - full charged capacity / designed capacity.
    Result: WARN when a battery wear is over -MaxWearPercent; NOT APPLICABLE when the machine has
    no battery (desktop, server, virtual machine). When the firmware does not report capacities
    the battery is listed and the check passes. Read-only; use it as a script check.

.PARAMETER MaxWearPercent
    Highest accepted wear in percent (0-100). Default 40.

.EXAMPLE
    -MaxWearPercent 30

.NOTES
    Name:       Hardware - Battery health
    GUID:       9fd1b94f-a2aa-4e34-89f0-23223b57895c
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); any user can read battery data
    Exit codes: 0 OK | 1 FAIL (error) | 2 WARN (wear over limit) | 3 NOT APPLICABLE (no battery)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxWearPercent = 40
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
    return ([string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied|0x80070005')
}

# Reads a root\wmi battery class; returns @() when the class is missing (no battery driver).
function Get-WmiBatteryClass([string]$ClassName) {
    try { return @(Get-CimInstance -Namespace 'root\wmi' -ClassName $ClassName -ErrorAction Stop) }
    catch {
        if (Test-AccessDenied $_) { $script:denied = $true }
        return @()
    }
}

# InstanceName looks like "ACPI\PNP0C0A\1_0"; keys are matched case-insensitively.
function ConvertTo-IndexByInstance([object[]]$Items) {
    $h = @{}
    foreach ($i in $Items) { if ($i.InstanceName) { $h[([string]$i.InstanceName).ToLowerInvariant()] = $i } }
    return $h
}

$statusNames = @{
    1 = 'discharging'; 2 = 'on AC'; 3 = 'fully charged'; 4 = 'low'; 5 = 'critical'; 6 = 'charging'
    7 = 'charging (high)'; 8 = 'charging (low)'; 9 = 'charging (critical)'; 10 = 'undefined'; 11 = 'partially charged'
}

$exitCode = 0
$script:denied = $false
try {
    if ($MaxWearPercent -lt 1 -or $MaxWearPercent -gt 100) { $MaxWearPercent = 40 }

    $w32 = @()
    try { $w32 = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) }
    catch { if (Test-AccessDenied $_) { $script:denied = $true } }

    $static = @(Get-WmiBatteryClass 'BatteryStaticData')
    $full = ConvertTo-IndexByInstance (Get-WmiBatteryClass 'BatteryFullChargedCapacity')
    $cycles = ConvertTo-IndexByInstance (Get-WmiBatteryClass 'BatteryCycleCount')

    if (-not $w32.Count -and -not $static.Count) {
        if ($script:denied) { Write-Output 'FAIL: access denied reading battery data (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
        Write-Output 'INFO: no battery found (desktop, server or virtual machine)'
        $host.SetShouldExit(3); exit 3
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]
    $measured = 0
    $n = 0
    foreach ($s in $static) {
        $n++
        $key = ([string]$s.InstanceName).ToLowerInvariant()
        $name = ConvertTo-AsciiText ('{0} {1}' -f [string]$s.ManufactureName, [string]$s.DeviceName)
        if (-not $name) { $name = 'Battery ' + $n }
        $design = [long]$s.DesignedCapacity
        $fullCap = 0
        if ($full.ContainsKey($key)) { $fullCap = [long]$full[$key].FullChargedCapacity }
        $parts = New-Object System.Collections.Generic.List[string]
        if ($design -gt 0 -and $fullCap -gt 0) {
            $wear = [math]::Round((1 - ($fullCap / $design)) * 100, 0)
            if ($wear -lt 0) { $wear = 0 }
            $measured++
            $parts.Add(('wear {0}%' -f $wear)) | Out-Null
            $parts.Add(('full {0} / design {1} mWh' -f $fullCap, $design)) | Out-Null
            if ($wear -gt $MaxWearPercent) { $warns.Add(('{0} wear {1}% over {2}%' -f $name, $wear, $MaxWearPercent)) | Out-Null }
        }
        else {
            $parts.Add('capacity not reported by the firmware') | Out-Null
        }
        if ($cycles.ContainsKey($key) -and [long]$cycles[$key].CycleCount -gt 0) {
            $parts.Add(('{0} cycles' -f $cycles[$key].CycleCount)) | Out-Null
        }
        $lines.Add(('INFO: {0} | {1}' -f $name, ($parts -join ', '))) | Out-Null
    }
    foreach ($b in $w32) {
        $st = [int]$b.BatteryStatus
        $stText = if ($statusNames.ContainsKey($st)) { $statusNames[$st] } else { 'status ' + $st }
        $charge = if ($null -ne $b.EstimatedChargeRemaining) { [string]$b.EstimatedChargeRemaining + '%' } else { '?' }
        $lines.Add(('INFO: {0} | {1} | charge {2} | {3}' -f (ConvertTo-AsciiText ([string]$b.Name)), $stText, $charge, (ConvertTo-AsciiText ([string]$b.Status)))) | Out-Null
    }
    if (-not $static.Count) { $lines.Add('INFO: capacity data (root\wmi) not available; wear not measured') | Out-Null }

    $count = [math]::Max($static.Count, $w32.Count)
    if ($warns.Count) {
        Write-Output ('WARN: ' + ($warns -join '; '))
        $exitCode = 2
    }
    elseif ($measured) {
        Write-Output ('OK: {0} battery(ies), wear within {1}%' -f $count, $MaxWearPercent)
    }
    else {
        Write-Output ('OK: {0} battery(ies), wear not measurable' -f $count)
    }
    $budget = 3800
    foreach ($l in ($lines | Select-Object -First 20)) {
        $t = ConvertTo-AsciiText $l
        $budget -= ($t.Length + 2)
        if ($budget -lt 0) { break }
        Write-Output $t
    }
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading battery data (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not read battery data: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
