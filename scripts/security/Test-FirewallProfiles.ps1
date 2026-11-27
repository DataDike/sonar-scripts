#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that the Windows Firewall profiles are enabled and block inbound traffic by default.

.DESCRIPTION
    Reads the effective state (policy store ActiveStore, so Group Policy is included) of the
    Domain, Private and Public profiles: Enabled and DefaultInboundAction. It also looks for a
    third-party firewall registered in Security Center (root/SecurityCenter2 FirewallProduct,
    client Windows only; errors are ignored). When an enabled third-party firewall is registered,
    a disabled Windows Firewall profile is reported as WARN instead of FAIL. Read-only.

.PARAMETER Profiles
    Profiles to check: Domain, Private and/or Public, as a list or one comma-separated string.
    Default Domain, Private, Public.

.EXAMPLE
    -Profiles Private,Public

.NOTES
    Name:       Security - Firewall profiles
    GUID:       88daaf46-ca57-4f3a-9141-6a2e8139d2ac
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator not required)
    Exit codes: 0 OK | 1 FAIL (profile disabled, or error) | 2 WARN (inbound default Allow, or disabled with a third-party firewall)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string[]]$Profiles = @('Domain', 'Private', 'Public')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

$exitCode = 0
try {
    # Normalize -Profiles: a list, or one "Private,Public" string when passed through -File
    $wanted = @()
    foreach ($item in $Profiles) {
        foreach ($tok in ([string]$item -split '[,;\s]+')) {
            if (-not $tok) { continue }
            $match = @('Domain', 'Private', 'Public') | Where-Object { $_ -eq $tok }
            if (-not $match) { throw ('invalid profile name: ' + $tok + ' (use Domain, Private, Public)') }
            if ($wanted -notcontains $match) { $wanted += $match }
        }
    }
    $Profiles = $wanted

    # Third-party firewall (Security Center exists on client Windows only)
    $thirdParty = @()
    try {
        foreach ($fp in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop)) {
            $state = [int]$fp.productState
            $enabled = (($state -band 0x1000) -ne 0)
            $thirdParty += [pscustomobject]@{ Name = [string]$fp.displayName; Enabled = $enabled }
        }
    }
    catch { Write-Verbose ('SecurityCenter2 not available: ' + $_.Exception.Message) }
    $thirdPartyOn = @($thirdParty | Where-Object { $_.Enabled }).Count -gt 0

    $fails = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]

    $fwProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $Profiles -ErrorAction Stop)
    foreach ($p in $fwProfiles) {
        $on = ([string]$p.Enabled -eq 'True')
        $inbound = [string]$p.DefaultInboundAction
        # NotConfigured means the Windows default, which is Block
        $effectiveInbound = if ($inbound -eq 'NotConfigured') { 'Block' } else { $inbound }
        $info.Add(('INFO: profile {0} enabled={1} inbound={2} outbound={3}' -f $p.Name, $on, $effectiveInbound, $p.DefaultOutboundAction)) | Out-Null
        if (-not $on) {
            if ($thirdPartyOn) { $warns.Add("$($p.Name) profile disabled (third-party firewall active)") | Out-Null }
            else { $fails.Add("$($p.Name) profile disabled") | Out-Null }
        }
        elseif ($effectiveInbound -eq 'Allow') {
            $warns.Add("$($p.Name) profile allows inbound by default") | Out-Null
        }
    }

    if ($fails.Count) {
        Write-Line ('FAIL: Windows Firewall ' + ($fails -join '; '))
        $exitCode = 1
    }
    elseif ($warns.Count) {
        Write-Line ('WARN: Windows Firewall ' + ($warns -join '; '))
        $exitCode = 2
    }
    else {
        Write-Line ('OK: Windows Firewall enabled with inbound Block on {0}' -f ($Profiles -join ', '))
    }
    $info | ForEach-Object { Write-Line $_ }
    if ($thirdParty.Count) {
        foreach ($t in $thirdParty) { Write-Line ('INFO: third-party firewall "{0}" enabled={1}' -f $t.Name, $t.Enabled) }
    }
    else {
        Write-Line 'INFO: no third-party firewall registered in Security Center'
    }
}
catch {
    Write-Line ('FAIL: could not read firewall profiles: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
