#Requires -Version 5.1
<#
.SYNOPSIS
    Finds machine certificates that expire soon or have recently expired.

.DESCRIPTION
    Reads the LocalMachine\My store (and, optionally, WebHosting and Remote Desktop) through the
    Cert: drive and reports, per certificate: subject CN, issuer CN, NotAfter, days left and the
    first 8 characters of the thumbprint. Only certificates with a private key are considered by
    default (the ones a service actually uses). Read-only: keys are never read or exported.
    Certificates that expired more than -IgnoreExpiredAfterDays ago are ignored, and an expiring
    certificate is not counted when the same store holds a newer certificate with the same subject
    that is valid for longer than -WarnDays (it was renewed); both are shown as INFO.

.PARAMETER WarnDays
    WARN when a certificate expires within this many days. Default 30.

.PARAMETER FailDays
    FAIL when a certificate expires within this many days or has expired. Default 7.

.PARAMETER IgnoreExpiredAfterDays
    Ignore certificates that expired more than this many days ago. Default 90.

.PARAMETER OnlyWithPrivateKey
    Only certificates with a private key. Default $true; pass -OnlyWithPrivateKey:$false for all.

.PARAMETER IncludeWebHosting
    Also read LocalMachine\WebHosting (IIS centralized certificates).

.PARAMETER IncludeRemoteDesktop
    Also read LocalMachine\Remote Desktop (RDP listener certificate).

.EXAMPLE
    -WarnDays 45 -FailDays 10 -IncludeWebHosting -IncludeRemoteDesktop

.NOTES
    Name:       Security - Expiring certificates
    GUID:       31a245cb-f5ed-45fa-8061-fad36f31af04
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator not required)
    Exit codes: 0 OK | 1 FAIL (expires within -FailDays or expired, or error) | 2 WARN (expires within -WarnDays)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$WarnDays = 30,
    [int]$FailDays = 7,
    [int]$IgnoreExpiredAfterDays = 90,
    [switch]$OnlyWithPrivateKey = $true,
    [switch]$IncludeWebHosting,
    [switch]$IncludeRemoteDesktop
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

function Limit-Text([string]$Text, [int]$Max) {
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max - 3) + '...'
}

$simple = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName

$exitCode = 0
try {
    if ($FailDays -gt $WarnDays) { throw 'FailDays must not be greater than WarnDays' }
    $stores = @('My')
    if ($IncludeWebHosting) { $stores += 'WebHosting' }
    if ($IncludeRemoteDesktop) { $stores += 'Remote Desktop' }

    $now = Get-Date
    $items = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    $scanned = 0

    foreach ($store in $stores) {
        $path = 'Cert:\LocalMachine\' + $store
        if (-not (Test-Path -LiteralPath $path)) { $notes.Add('store ' + $store + ' not present') | Out-Null; continue }
        $certs = @(Get-ChildItem -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] })
        if ($OnlyWithPrivateKey) { $certs = @($certs | Where-Object { $_.HasPrivateKey }) }
        $scanned += $certs.Count
        foreach ($c in $certs) {
            $days = [int][math]::Floor(($c.NotAfter - $now).TotalDays)
            if ($days -ge $WarnDays) { continue }
            $subject = $c.GetNameInfo($simple, $false)
            if (-not $subject) { $subject = $c.Subject }
            $issuer = $c.GetNameInfo($simple, $true)
            $obj = [pscustomobject]@{
                Store = $store; Subject = (Limit-Text $subject 50); Issuer = (Limit-Text $issuer 30)
                NotAfter = $c.NotAfter; Days = $days; Thumb = $c.Thumbprint.Substring(0, 8); State = ''
            }
            if ($days -lt -$IgnoreExpiredAfterDays) { continue }
            # Renewed: same store, same subject, valid beyond -WarnDays
            $renewed = @($certs | Where-Object { $_.Subject -eq $c.Subject -and $_.Thumbprint -ne $c.Thumbprint -and ($_.NotAfter - $now).TotalDays -ge $WarnDays }).Count -gt 0
            if ($renewed) { $obj.State = 'renewed' }
            elseif ($days -lt $FailDays) { $obj.State = 'fail' }
            else { $obj.State = 'warn' }
            $items.Add($obj) | Out-Null
        }
    }

    $failItems = @($items | Where-Object { $_.State -eq 'fail' })
    $warnItems = @($items | Where-Object { $_.State -eq 'warn' })
    $scope = if ($OnlyWithPrivateKey) { 'with private key' } else { 'in total' }
    if ($failItems.Count) {
        Write-Line ('FAIL: {0} certificate(s) expired or expiring within {1} days, {2} within {3} days ({4} scanned {5})' -f $failItems.Count, $FailDays, $warnItems.Count, $WarnDays, $scanned, $scope)
        $exitCode = 1
    }
    elseif ($warnItems.Count) {
        Write-Line ('WARN: {0} certificate(s) expiring within {1} days ({2} scanned {3})' -f $warnItems.Count, $WarnDays, $scanned, $scope)
        $exitCode = 2
    }
    else {
        Write-Line ('OK: no certificate expiring within {0} days ({1} scanned {2})' -f $WarnDays, $scanned, $scope)
    }

    $n = 0
    foreach ($i in ($items | Sort-Object -Property @{ Expression = { if ($_.State -eq 'renewed') { 1 } else { 0 } } }, Days)) {
        if ($n -ge 25) { Write-Line ('INFO: {0} more certificate(s) not shown' -f ($items.Count - $n)); break }
        $prefix = switch ($i.State) { 'fail' { 'FAIL' } 'warn' { 'WARN' } default { 'INFO' } }
        $when = if ($i.Days -lt 0) { 'expired {0} d ago' -f (-$i.Days) } else { '{0} d left' -f $i.Days }
        $extra = if ($i.State -eq 'renewed') { ' | renewed, ignored' } else { '' }
        Write-Line ('{0}: {1} | CN={2} | issuer {3} | {4:yyyy-MM-dd} | {5} | {6}{7}' -f $prefix, $i.Store, $i.Subject, $i.Issuer, $i.NotAfter, $when, $i.Thumb, $extra)
        $n++
    }
    foreach ($note in $notes) { Write-Line ('INFO: ' + $note) }
}
catch {
    Write-Line ('FAIL: could not read certificates: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
