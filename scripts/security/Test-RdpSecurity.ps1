#Requires -Version 5.1
<#
.SYNOPSIS
    Checks Remote Desktop exposure: enabled, Network Level Authentication, security layer, port, firewall.

.DESCRIPTION
    Reads the effective Remote Desktop settings (Group Policy values under
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services win over the local ones):
    fDenyTSConnections, UserAuthentication (NLA), SecurityLayer and the RDP-Tcp PortNumber, and
    lists the enabled rules of the built-in "Remote Desktop" firewall group (selected by its
    language-neutral group id @FirewallAPI.dll,-28752) with their profiles. Read-only.
    Rules:
      - RDP disabled                                    -> exit 3 (not applicable)
      - RDP enabled without NLA                         -> exit 1 (FAIL)
      - firewall rule open on Public/Any profile, or
        SecurityLayer 0 (legacy RDP encryption, no TLS) -> exit 2 (WARN)
      - otherwise                                       -> exit 0 (OK)

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Security - RDP security
    GUID:       cead6105-d0b4-470a-9c7f-f1108a22aa52
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator not required)
    Exit codes: 0 OK | 1 FAIL (no NLA, or error) | 2 WARN (Public profile or legacy security layer) | 3 NOT APPLICABLE (RDP disabled)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

function Get-RegValue([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-EffectiveValue([string]$Name, [string]$LocalPath, $Default) {
    $pol = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' $Name
    if ($null -ne $pol) { return [pscustomobject]@{ Value = $pol; Source = 'policy' } }
    $loc = Get-RegValue $LocalPath $Name
    if ($null -ne $loc) { return [pscustomobject]@{ Value = $loc; Source = 'local' } }
    return [pscustomobject]@{ Value = $Default; Source = 'default' }
}

$tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpKey = "$tsKey\WinStations\RDP-Tcp"
$exitCode = 0
try {
    $deny = Get-EffectiveValue 'fDenyTSConnections' $tsKey 1
    if ([int]$deny.Value -ne 0) {
        Write-Line ('OK: Remote Desktop is disabled (fDenyTSConnections={0}, {1}); not applicable' -f $deny.Value, $deny.Source)
        $host.SetShouldExit(3); exit 3
    }

    $nla = Get-EffectiveValue 'UserAuthentication' $rdpKey 1
    $layer = Get-EffectiveValue 'SecurityLayer' $rdpKey 2
    $port = Get-RegValue $rdpKey 'PortNumber'
    if ($null -eq $port) { $port = 3389 }

    $layerName = switch ([int]$layer.Value) { 0 { 'RDP (legacy)' } 1 { 'Negotiate' } 2 { 'TLS' } default { 'unknown' } }

    # Firewall rules of the built-in Remote Desktop group (language-neutral id)
    $rules = @()
    $fwError = $null
    try {
        $rules = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Inbound' })
    }
    catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { $fwError = $_.Exception.Message }
    }
    $profileSet = @{}
    foreach ($r in $rules) {
        foreach ($p in ([string]$r.Profile -split ',\s*')) { if ($p) { $profileSet[$p] = $true } }
    }
    $openProfiles = @($profileSet.Keys | Sort-Object)
    $publicOpen = $profileSet.ContainsKey('Any') -or $profileSet.ContainsKey('Public')

    $fails = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]
    if ([int]$nla.Value -ne 1) { $fails.Add('Network Level Authentication is not required') | Out-Null }
    if ($publicOpen) { $warns.Add('Remote Desktop firewall rule enabled on the Public profile') | Out-Null }
    if ([int]$layer.Value -eq 0) { $warns.Add('security layer is legacy RDP encryption (no TLS)') | Out-Null }

    if ($fails.Count) {
        Write-Line ('FAIL: Remote Desktop enabled and ' + ((@($fails) + @($warns)) -join '; '))
        $exitCode = 1
    }
    elseif ($warns.Count) {
        Write-Line ('WARN: Remote Desktop enabled with NLA but ' + ($warns -join '; '))
        $exitCode = 2
    }
    else {
        if ($fwError) { Write-Line 'OK: Remote Desktop enabled with NLA and TLS-capable security layer (firewall exposure not checked)' }
        else { Write-Line 'OK: Remote Desktop enabled with NLA, TLS-capable security layer and not open on Public' }
    }

    Write-Line ('INFO: NLA (UserAuthentication)={0} ({1})' -f $nla.Value, $nla.Source)
    Write-Line ('INFO: SecurityLayer={0} {1} ({2})' -f $layer.Value, $layerName, $layer.Source)
    Write-Line ('INFO: listening port {0}{1}' -f $port, $(if ([int]$port -ne 3389) { ' (non-default; the built-in firewall rules only cover 3389)' } else { '' }))
    if ($fwError) { Write-Line ('INFO: firewall rules not readable: ' + $fwError) }
    elseif ($openProfiles.Count) { Write-Line ('INFO: {0} enabled inbound Remote Desktop rule(s), profiles: {1}' -f $rules.Count, ($openProfiles -join ', ')) }
    else { Write-Line 'INFO: no enabled inbound rule in the built-in Remote Desktop firewall group' }
}
catch {
    Write-Line ('FAIL: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
