#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the connected monitors: manufacturer, model, serial number, year and connection type.

.DESCRIPTION
    Reads the EDID data that Windows exposes in root\wmi: WmiMonitorID (manufacturer code, model,
    serial number, week/year of manufacture, decoded from UInt16 arrays), WmiMonitorConnectionParams
    (connection: HDMI, DisplayPort, DVI, VGA, internal panel...) and WmiMonitorBasicDisplayParams
    (screen size, converted to a diagonal in inches). Monitors that are no longer connected are
    marked "inactive". Inventory action, read-only.
    Exit 0 with the list, 3 when no monitor is reported (server, virtual machine, headless).

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Inventory - Monitors
    GUID:       e2755dbe-4d6d-499c-8594-62599ce3c7db
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); any user can read monitor data
    Exit codes: 0 OK | 1 FAIL (error) | 3 NOT APPLICABLE (no monitor reported)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param()

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

# EDID strings come as UInt16 arrays padded with zeros.
function ConvertFrom-EdidArray($Value) {
    if ($null -eq $Value) { return '' }
    $chars = foreach ($c in @($Value)) { if ([int]$c -gt 0) { [char][int]$c } }
    return (ConvertTo-AsciiText (-join $chars))
}

function Get-RootWmi([string]$ClassName) {
    try { return @(Get-CimInstance -Namespace 'root\wmi' -ClassName $ClassName -ErrorAction Stop) }
    catch {
        if (Test-AccessDenied $_) { $script:denied = $true }
        return @()
    }
}

# Common PNP manufacturer ids (EDID); anything else is printed as the 3-letter code.
$vendors = @{
    ACR = 'Acer'; AOC = 'AOC'; APP = 'Apple'; AUO = 'AU Optronics'; AUS = 'Asus'; BNQ = 'BenQ'; BOE = 'BOE'
    CMN = 'Innolux'; DEL = 'Dell'; ENC = 'Eizo'; GSM = 'LG'; HPN = 'HP'; HWP = 'HP'; IVM = 'Iiyama'
    LEN = 'Lenovo'; LGD = 'LG Display'; MSI = 'MSI'; NEC = 'NEC'; PHL = 'Philips'; SAM = 'Samsung'
    SDC = 'Samsung Display'; SEC = 'Samsung'; SHP = 'Sharp'; SNY = 'Sony'; VSC = 'ViewSonic'
    CMO = 'Chi Mei'; IVO = 'InfoVision'; MEI = 'Panasonic'; FUS = 'Fujitsu'; GBT = 'Gigabyte'; HKC = 'HKC'
}

function Get-ConnectionName($Value) {
    if ($null -eq $Value) { return '?' }
    $v = [int64]$Value
    if ($v -lt 0) { $v = $v + 4294967296 }
    switch ($v) {
        -2 { return 'uninitialized' }
        4294967294 { return 'uninitialized' }
        4294967295 { return 'other' }
        0 { return 'VGA' }
        1 { return 'S-Video' }
        2 { return 'Composite' }
        3 { return 'Component' }
        4 { return 'DVI' }
        5 { return 'HDMI' }
        6 { return 'LVDS (internal)' }
        8 { return 'D-Jpn' }
        9 { return 'SDI' }
        10 { return 'DisplayPort' }
        11 { return 'DisplayPort (internal)' }
        12 { return 'UDI' }
        13 { return 'UDI (internal)' }
        14 { return 'SDTV dongle' }
        15 { return 'Miracast (wireless)' }
        16 { return 'indirect (wired)' }
        17 { return 'indirect (virtual)' }
        2147483648 { return 'internal panel' }
    }
    return ('type ' + $v)
}

$exitCode = 0
$script:denied = $false
try {
    $ids = @(Get-RootWmi 'WmiMonitorID')
    if (-not $ids.Count) {
        if ($script:denied) { Write-Output 'FAIL: access denied reading monitor data (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
        Write-Output 'INFO: no monitor reported (server, virtual machine or no display connected)'
        $host.SetShouldExit(3); exit 3
    }
    $conn = @{}
    foreach ($c in (Get-RootWmi 'WmiMonitorConnectionParams')) { $conn[([string]$c.InstanceName).ToLowerInvariant()] = $c }
    $basic = @{}
    foreach ($b in (Get-RootWmi 'WmiMonitorBasicDisplayParams')) { $basic[([string]$b.InstanceName).ToLowerInvariant()] = $b }

    $lines = New-Object System.Collections.Generic.List[string]
    $active = 0
    foreach ($m in $ids) {
        $key = ([string]$m.InstanceName).ToLowerInvariant()
        $code = ConvertFrom-EdidArray $m.ManufacturerName
        $maker = if ($vendors.ContainsKey($code)) { $vendors[$code] } elseif ($code) { $code } else { '?' }
        $model = ConvertFrom-EdidArray $m.UserFriendlyName
        if (-not $model) { $model = 'product ' + (ConvertFrom-EdidArray $m.ProductCodeID) }
        $serial = ConvertFrom-EdidArray $m.SerialNumberID
        if (-not $serial -or $serial -eq '0') { $serial = '-' }
        $year = if ([int]$m.YearOfManufacture -gt 1990) { [string]$m.YearOfManufacture } else { '?' }
        $type = if ($conn.ContainsKey($key)) { Get-ConnectionName $conn[$key].VideoOutputTechnology } else { '?' }
        $size = '?'
        if ($basic.ContainsKey($key)) {
            $h = [double]$basic[$key].MaxHorizontalImageSize
            $v = [double]$basic[$key].MaxVerticalImageSize
            if ($h -gt 0 -and $v -gt 0) { $size = ('{0}in' -f [math]::Round([math]::Sqrt($h * $h + $v * $v) / 2.54, 0)) }
        }
        $state = if ($m.Active) { $active++; 'active' } else { 'inactive' }
        $lines.Add(('INFO: {0} | {1} | serial {2} | year {3} | {4} | {5} | {6}' -f $maker, $model, $serial, $year, $type, $size, $state)) | Out-Null
    }

    Write-Output ('OK: {0} monitor(s) reported, {1} active' -f $ids.Count, $active)
    $budget = 3800
    $printed = 0
    foreach ($l in $lines) {
        $t = ConvertTo-AsciiText $l
        if ($budget - ($t.Length + 2) -lt 0) { break }
        $budget -= ($t.Length + 2)
        Write-Output $t
        $printed++
    }
    if ($printed -lt $lines.Count) { Write-Output ('INFO: {0} more not shown' -f ($lines.Count - $printed)) }
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading monitor data (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not read monitor data: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
