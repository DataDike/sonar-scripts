#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that the SMBv1 protocol is disabled on the server and client side.

.DESCRIPTION
    Server side: Get-SmbServerConfiguration EnableSMB1Protocol; when that cmdlet fails the script
    falls back to the SMB1 value under LanmanServer\Parameters and the state of the SMBv1 server
    driver (srv). Client side: start type of the mrxsmb10 driver (Start = 4 means disabled, a missing
    key means removed) and, on client Windows, the optional feature SMB1Protocol
    (Get-WindowsOptionalFeature needs administrator rights; failures are ignored). Read-only.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Security - SMBv1 disabled
    GUID:       9d5800f9-ff6c-48b4-9338-942dab981a7d
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (SMBv1 server enabled or state unknown) | 2 WARN (only SMBv1 client enabled)
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

$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$exitCode = 0
try {
    $info = New-Object System.Collections.Generic.List[string]

    # Optional feature (client Windows, needs admin)
    $featureState = $null
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($f) { $featureState = [string]$f.State }
    }
    catch { Write-Verbose ('optional feature not readable: ' + $_.Exception.Message) }
    $info.Add('INFO: optional feature SMB1Protocol: ' + $(if ($featureState) { $featureState } else { 'not available (server OS or no admin rights)' })) | Out-Null

    # Server side
    $server = $null   # $true enabled, $false disabled, $null unknown
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        $server = [bool]$cfg.EnableSMB1Protocol
        $info.Add('INFO: server EnableSMB1Protocol = ' + $server) | Out-Null
    }
    catch {
        $info.Add('INFO: Get-SmbServerConfiguration failed: ' + $_.Exception.Message.Trim()) | Out-Null
        $regSmb1 = Get-RegValue "$svcRoot\LanmanServer\Parameters" 'SMB1'
        $srvStart = Get-RegValue "$svcRoot\srv" 'Start'
        $info.Add(('INFO: server fallback: SMB1 value={0} srv driver start={1}' -f $(if ($null -eq $regSmb1) { 'absent' } else { $regSmb1 }), $(if ($null -eq $srvStart) { 'absent' } else { $srvStart }))) | Out-Null
        if ($featureState -eq 'Disabled' -or $null -eq $srvStart -or $srvStart -eq 4 -or $regSmb1 -eq 0) { $server = $false }
        elseif ($featureState -eq 'Enabled' -or $regSmb1 -eq 1) { $server = $true }
    }

    # Client side
    $mrxStart = Get-RegValue "$svcRoot\mrxsmb10" 'Start'
    $client = $true
    if ($null -eq $mrxStart) { $client = $false; $info.Add('INFO: client driver mrxsmb10 not installed') | Out-Null }
    else {
        if ($mrxStart -eq 4) { $client = $false }
        $info.Add(('INFO: client driver mrxsmb10 start={0} ({1})' -f $mrxStart, $(if ($mrxStart -eq 4) { 'disabled' } else { 'enabled' }))) | Out-Null
    }
    if ($featureState -eq 'Enabled' -and -not $client) {
        $info.Add('INFO: feature SMB1Protocol is enabled even though the client driver is disabled') | Out-Null
    }

    if ($server -eq $true) {
        Write-Line 'FAIL: SMBv1 server protocol is enabled'
        $exitCode = 1
    }
    elseif ($null -eq $server) {
        Write-Line 'FAIL: could not determine the SMBv1 server state (run as administrator / SYSTEM)'
        $exitCode = 1
    }
    elseif ($client) {
        Write-Line 'WARN: SMBv1 server disabled but SMBv1 client is enabled'
        $exitCode = 2
    }
    else {
        Write-Line 'OK: SMBv1 is disabled (server and client)'
    }
    $info | ForEach-Object { Write-Line $_ }
}
catch {
    Write-Line ('FAIL: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
