#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the Windows license (activation) status.

.DESCRIPTION
    Reads SoftwareLicensingProduct for the Windows application id and the products that have
    a product key installed. Prints the status, product name, channel and only the last
    5 characters of the product key (never the full key). Changes nothing.
    Use it as a check: Licensed exits 0, grace or notification exits 2 (warning),
    unlicensed or no key exits 1.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Inventory - Windows activation
    GUID:       c7ae25c4-4a3e-4642-8607-cbddd62a3e5e
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK (licensed) | 1 FAIL (unlicensed, no key, error) | 2 WARN (grace or notification)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output must stay ASCII: strip accents from localized system strings, replace anything else.
function ConvertTo-AsciiText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $d = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $d.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -eq [System.Globalization.UnicodeCategory]::NonSpacingMark) { continue }
        if ([int]$ch -ge 32 -and [int]$ch -le 126) { [void]$sb.Append($ch) } else { [void]$sb.Append('?') }
    }
    return $sb.ToString().Trim()
}

$statusNames = @{
    0 = 'Unlicensed'
    1 = 'Licensed'
    2 = 'Initial grace period'
    3 = 'Additional grace period (hardware change)'
    4 = 'Non-genuine grace period'
    5 = 'Notification'
    6 = 'Extended grace period'
}

$exitCode = 0
try {
    $filter = "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
    $products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter)

    if ($products.Count -eq 0) {
        Write-Output "FAIL: no Windows product key is installed"
        $exitCode = 1
    }
    else {
        # Prefer a licensed product, then the one with the lowest (best) status code
        $best = $products | Sort-Object -Property @{ Expression = { if ([int]$_.LicenseStatus -eq 1) { 0 } else { 1 } } }, @{ Expression = { [int]$_.LicenseStatus } } | Select-Object -First 1
        $code = [int]$best.LicenseStatus
        $statusText = if ($statusNames.ContainsKey($code)) { $statusNames[$code] } else { "Unknown status $code" }

        if ($code -eq 1) {
            Write-Output ("OK: Windows is licensed")
        }
        elseif ($code -ge 2 -and $code -le 6) {
            Write-Output ("WARN: Windows is not fully activated: {0}" -f $statusText)
            $exitCode = 2
        }
        else {
            Write-Output ("FAIL: Windows is not activated: {0}" -f $statusText)
            $exitCode = 1
        }

        foreach ($p in $products) {
            $c = [int]$p.LicenseStatus
            $st = if ($statusNames.ContainsKey($c)) { $statusNames[$c] } else { "Unknown status $c" }
            $key = [string]$p.PartialProductKey
            if ($key.Length -gt 5) { $key = $key.Substring($key.Length - 5) }
            $channel = ConvertTo-AsciiText ([string]$p.ProductKeyChannel)
            if (-not $channel) { $channel = 'unknown channel' }
            Write-Output ("INFO: {0} | {1} | {2} | key ending {3}" -f (ConvertTo-AsciiText $p.Name), $st, $channel, $key)
            Write-Output ("INFO: Description: {0}" -f (ConvertTo-AsciiText $p.Description))
            if ($c -ne 1 -and [int]$p.GracePeriodRemaining -gt 0) {
                Write-Output ("INFO: Grace period remaining: {0} day(s)" -f [math]::Floor([int]$p.GracePeriodRemaining / 1440))
            }
        }
    }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
