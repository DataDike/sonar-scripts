#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the installed Microsoft Office: Click-to-Run version, channel and products, and MSI editions.

.DESCRIPTION
    Click-to-Run (Microsoft 365 Apps, Office 2019/2021/2024): reads
    HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration (VersionToReport, Platform, update
    channel from UpdateChannel or CDNBaseUrl mapped to its name, UpdatesEnabled, ProductReleaseIds)
    plus the update channel set by policy, if any, and the Click-to-Run service state.
    MSI Office (2010-2016 volume editions): reads the machine Uninstall keys (OfficeNN.PRODUCT
    entries and visible product codes ending in 0FF1CE).
    License keys and activation data are never read or printed. Inventory action, read-only.
    Exit 0 when Office is found, 3 when no Office is installed.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Inventory - Microsoft Office
    GUID:       ee3d8a6d-95e7-4434-bab2-9a7af2f4fd26
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); any user can read these keys
    Exit codes: 0 OK | 1 FAIL (error) | 3 NOT APPLICABLE (no Office installed)
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

function Get-ShortText([string]$Text, [int]$Max) {
    $t = ConvertTo-AsciiText $Text
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Test-AccessDenied($ErrorRecord) {
    return ($ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or
        [string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied')
}

# Office CDN channel ids (the GUID in CDNBaseUrl / UpdateChannel)
$channels = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Channel (Preview)'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
    'f2e724c1-748f-4b47-8fb8-8e0d210e9208' = 'Office 2019 Perpetual Enterprise (LTSC)'
    '5030841d-c919-4594-8d2d-84ae4f96e58e' = 'Office LTSC 2021 Perpetual Enterprise'
    '7983bac0-e531-40cf-be00-fd24fe66619c' = 'Office LTSC 2024 Perpetual Enterprise'
}
# Policy updatebranch values
$branches = @{
    'Current' = 'Current Channel'; 'FirstReleaseCurrent' = 'Current Channel (Preview)'
    'MonthlyEnterprise' = 'Monthly Enterprise Channel'; 'Deferred' = 'Semi-Annual Enterprise Channel'
    'FirstReleaseDeferred' = 'Semi-Annual Enterprise Channel (Preview)'; 'InsiderFast' = 'Beta Channel'
}

function Get-ChannelName([string]$Url) {
    if (-not $Url) { return $null }
    if ($Url -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
        $g = $Matches[1].ToLowerInvariant()
        if ($channels.ContainsKey($g)) { return $channels[$g] }
        return ('unknown channel ' + $g)
    }
    if ($Url -match '^\w+$' -and $branches.ContainsKey($Url)) { return $branches[$Url] }
    return 'custom source (local or network path)'
}

$exitCode = 0
try {
    $lines = New-Object System.Collections.Generic.List[string]
    $found = 0
    $denied = $false

    # --- Click-to-Run ---
    $c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $c2r = $null
    try { if (Test-Path -LiteralPath $c2rKey) { $c2r = Get-ItemProperty -LiteralPath $c2rKey -ErrorAction Stop } }
    catch { if (Test-AccessDenied $_) { $denied = $true } }
    $verdict = $null
    if ($c2r -and $c2r.VersionToReport) {
        $found++
        $ver = [string]$c2r.VersionToReport
        $plat = [string]$c2r.Platform
        $channel = $null
        $source = 'CDNBaseUrl'
        if ($c2r.UpdateChannel) { $channel = Get-ChannelName ([string]$c2r.UpdateChannel); $source = 'UpdateChannel' }
        elseif ($c2r.CDNBaseUrl) { $channel = Get-ChannelName ([string]$c2r.CDNBaseUrl) }
        if (-not $channel) { $channel = 'unknown' }
        $verdict = 'OK: Microsoft Office Click-to-Run {0} ({1}), {2}' -f $ver, $plat, $channel
        $products = @(([string]$c2r.ProductReleaseIds) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $lines.Add(('INFO: products: {0}' -f (Get-ShortText ($products -join ', ') 300))) | Out-Null
        $lines.Add(('INFO: channel {0} (from {1})' -f $channel, $source)) | Out-Null
        $upd = if ($null -eq $c2r.UpdatesEnabled) { 'not set (default enabled)' } else { [string]$c2r.UpdatesEnabled }
        $lines.Add(('INFO: updates enabled: {0}' -f $upd)) | Out-Null
        if ($c2r.SharedComputerLicensing -eq '1') { $lines.Add('INFO: shared computer activation enabled') | Out-Null }
        $culture = [string]$c2r.ClientCulture
        if ($culture) { $lines.Add(('INFO: language {0}' -f (Get-ShortText $culture 20))) | Out-Null }

        $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
        try {
            if (Test-Path -LiteralPath $polKey) {
                $pol = Get-ItemProperty -LiteralPath $polKey -ErrorAction Stop
                if ($pol.updatebranch) { $lines.Add(('INFO: policy update channel: {0}' -f (Get-ChannelName ([string]$pol.updatebranch)))) | Out-Null }
                if ($null -ne $pol.enableautomaticupdates) { $lines.Add(('INFO: policy automatic updates: {0}' -f [string]$pol.enableautomaticupdates)) | Out-Null }
            }
        }
        catch { Write-Verbose ('policy key: ' + $_.Exception.Message) }

        $svc = Get-Service -Name 'ClickToRunSvc' -ErrorAction SilentlyContinue
        if ($svc) { $lines.Add(('INFO: Click-to-Run service {0}' -f [string]$svc.Status)) | Out-Null }
        else { $lines.Add('INFO: Click-to-Run service not found') | Out-Null }
    }

    # --- Uninstall keys: MSI Office and the Click-to-Run product names ---
    $roots = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Bits = $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }) },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Bits = '32-bit' }
    )
    $msi = New-Object System.Collections.Generic.List[string]
    $c2rNames = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.Path)) { continue }
        $keys = @()
        try { $keys = @(Get-ChildItem -LiteralPath $r.Path -ErrorAction Stop) }
        catch { if (Test-AccessDenied $_) { $denied = $true }; continue }
        foreach ($k in $keys) {
            $kn = $k.PSChildName
            $isMsiSuite = $kn -match '^Office\d{2}\.[A-Za-z0-9]+$'
            $isMsiCode = $kn -match '0FF1CE\}$'
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop }
            catch { continue }
            $name = [string]$p.DisplayName
            if (-not $name) { continue }
            if ([string]$p.UninstallString -match '(?i)OfficeClickToRun\.exe') {
                if (-not $seen.ContainsKey($name)) { $seen[$name] = $true; $c2rNames.Add((Get-ShortText $name 70)) | Out-Null }
                continue
            }
            if (-not ($isMsiSuite -or $isMsiCode)) { continue }
            if ([string]$p.SystemComponent -eq '1' -or $p.ParentKeyName) { continue }
            if ($name -notmatch '(?i)office|visio|project|outlook|word|excel|powerpoint|access|publisher|onenote|skype|lync') { continue }
            $dedup = $name + '|' + [string]$p.DisplayVersion
            if ($seen.ContainsKey($dedup)) { continue }
            $seen[$dedup] = $true
            $msi.Add(('{0} {1} ({2})' -f (Get-ShortText $name 70), [string]$p.DisplayVersion, $r.Bits)) | Out-Null
        }
    }
    if ($c2rNames.Count) { $lines.Add(('INFO: installed as: {0}' -f (Get-ShortText ($c2rNames -join ', ') 400))) | Out-Null }
    if ($msi.Count) {
        $found++
        if (-not $verdict) { $verdict = 'OK: Microsoft Office (MSI) ' + $msi[0] }
        foreach ($m in $msi) { $lines.Add('INFO: MSI: ' + $m) | Out-Null }
    }

    if (-not $found) {
        if ($denied) { Write-Output 'FAIL: access denied reading the Office registry keys (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
        if ($c2rNames.Count) {
            Write-Output (ConvertTo-AsciiText ('OK: Microsoft Office Click-to-Run registered: ' + (Get-ShortText ($c2rNames -join ', ') 400)))
            Write-Output 'INFO: Click-to-Run configuration key missing or unreadable; version and channel unknown'
            $host.SetShouldExit(0); exit 0
        }
        Write-Output 'INFO: Microsoft Office not installed'
        $host.SetShouldExit(3); exit 3
    }
    if ($c2r -and $msi.Count) { $verdict += ' (also MSI Office installed)' }

    Write-Output (ConvertTo-AsciiText $verdict)
    $budget = 3700
    $printed = 0
    foreach ($l in $lines) {
        $t = ConvertTo-AsciiText $l
        if (($budget - ($t.Length + 2)) -lt 0) { break }
        $budget -= ($t.Length + 2)
        Write-Output $t
        $printed++
    }
    if ($printed -lt $lines.Count) { Write-Output ('INFO: {0} more not shown' -f ($lines.Count - $printed)) }
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading the Office registry keys (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not read Office information: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
