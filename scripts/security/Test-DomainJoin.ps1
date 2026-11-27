#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the Active Directory / Microsoft Entra join state and checks the domain secure channel.

.DESCRIPTION
    Parses "dsregcmd /status" (its field names are English on every Windows display language):
    AzureAdJoined, DomainJoined, EnterpriseJoined, WorkplaceJoined, TenantName, DeviceId (first
    8 characters only), whether an MDM URL is set, and the AzureAdPrt state. It also reads
    Win32_ComputerSystem (PartOfDomain, Domain) and, when the machine is in a domain, tests the
    secure channel with Test-ComputerSecureChannel (needs a domain controller and administrator
    rights; errors are reported as "unknown", not as a failure). The tenant id is never printed.
    WorkplaceJoined and AzureAdPrt belong to the account running the script (SYSTEM shows NO).
    Read-only.

.PARAMETER Require
    Join that must be present: None (report only), Domain (Active Directory), Entra (Microsoft
    Entra joined, including hybrid) or Any (either). Default None.

.EXAMPLE
    -Require Entra

.NOTES
    Name:       Security - Domain and Entra join
    GUID:       5044a7cb-8d43-41da-9c80-1ed6c30031f6
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator for the secure channel test)
    Exit codes: 0 OK | 1 FAIL (secure channel broken, required join missing, or error)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [ValidateSet('None', 'Domain', 'Entra', 'Any')]
    [string]$Require = 'None'
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
    # dsregcmd (Windows 10 and later). Keep the first value of each field.
    $ds = @{}
    $dsNote = $null
    $dsExe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    if (Test-Path -LiteralPath $dsExe) {
        try {
            foreach ($line in @(& $dsExe /status 2>&1)) {
                if ([string]$line -match '^\s*([A-Za-z][A-Za-z ]*?)\s+:\s?(.*)$') {
                    $k = $Matches[1].Trim(); $v = $Matches[2].Trim()
                    if (-not $ds.ContainsKey($k)) { $ds[$k] = $v }
                }
            }
            if ($ds.Count -eq 0) { $dsNote = 'dsregcmd returned no data' }
        }
        catch { $dsNote = 'dsregcmd failed: ' + $_.Exception.Message }
    }
    else { $dsNote = 'dsregcmd not available on this Windows' }

    function Get-Ds([string]$Key) { if ($ds.ContainsKey($Key)) { return [string]$ds[$Key] } return '' }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property PartOfDomain, Domain, Workgroup -ErrorAction Stop
    $inDomain = [bool]$cs.PartOfDomain
    $entra = ((Get-Ds 'AzureAdJoined') -eq 'YES')
    $hybrid = ($entra -and $inDomain)

    # Secure channel
    $channel = 'not applicable'
    $channelBroken = $false
    if ($inDomain) {
        try {
            if (Test-ComputerSecureChannel -ErrorAction Stop) { $channel = 'OK' }
            else { $channel = 'BROKEN'; $channelBroken = $true }
        }
        catch { $channel = 'unknown (' + $_.Exception.Message + ')' }
    }

    $joinText = if ($hybrid) { 'hybrid (Active Directory + Entra)' }
        elseif ($inDomain) { 'Active Directory' }
        elseif ($entra) { 'Microsoft Entra' }
        else { 'not joined (workgroup)' }

    $missing = $null
    switch ($Require) {
        'Domain' { if (-not $inDomain) { $missing = 'Active Directory join required' } }
        'Entra' { if (-not $entra) { $missing = 'Microsoft Entra join required' } }
        'Any' { if (-not ($inDomain -or $entra)) { $missing = 'Active Directory or Entra join required' } }
    }

    if ($channelBroken) {
        Write-Line ('FAIL: domain secure channel is broken ({0}, domain {1})' -f $joinText, $cs.Domain)
        $exitCode = 1
    }
    elseif ($missing) {
        Write-Line ('FAIL: {0}; machine is {1}' -f $missing, $joinText)
        $exitCode = 1
    }
    else {
        Write-Line ('OK: join state {0}' -f $joinText)
    }

    if ($inDomain) { Write-Line ('INFO: domain {0} | secure channel {1}' -f $cs.Domain, $channel) }
    else { Write-Line ('INFO: workgroup {0}' -f $cs.Workgroup) }
    if ($ds.Count) {
        Write-Line ('INFO: AzureAdJoined={0} DomainJoined={1} EnterpriseJoined={2} WorkplaceJoined={3}' -f (Get-Ds 'AzureAdJoined'), (Get-Ds 'DomainJoined'), (Get-Ds 'EnterpriseJoined'), (Get-Ds 'WorkplaceJoined'))
        $tenant = Get-Ds 'TenantName'
        if (-not $tenant) { $tenant = Get-Ds 'WorkplaceTenantName' }
        $devId = Get-Ds 'DeviceId'
        if ($devId.Length -gt 8) { $devId = $devId.Substring(0, 8) + '...' }
        $mdm = if ((Get-Ds 'MdmUrl')) { 'yes' } else { 'no' }
        $prt = Get-Ds 'AzureAdPrt'
        Write-Line ('INFO: tenant {0} | DeviceId {1} | MDM URL set {2} | AzureAdPrt {3}' -f $(if ($tenant) { $tenant } else { '-' }), $(if ($devId) { $devId } else { '-' }), $mdm, $(if ($prt) { $prt } else { '-' }))
    }
    if ($dsNote) { Write-Line ('INFO: ' + $dsNote) }
}
catch {
    Write-Line ('FAIL: could not read the join state: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
