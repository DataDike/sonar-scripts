#Requires -Version 5.1
<#
.SYNOPSIS
    Scores a Windows hardening baseline: one PASS/FAIL line per control and a total score.

.DESCRIPTION
    Evaluates a short list of well-known hardening controls from the registry, CIM and the
    service list. Read-only: nothing is changed.
      UAC         UAC enabled (EnableLUA=1) and admin consent prompt not disabled (ConsentPromptBehaviorAdmin not 0)
      LSA_PPL     LSA protection (RunAsPPL 1 or 2)
      VBS         Credential Guard running (Win32_DeviceGuard); the VBS state is shown as detail
      WDIGEST     WDigest UseLogonCredential is not 1 (no clear-text credentials in memory)
      LLMNR       LLMNR disabled by policy (DNSClient EnableMulticast=0)
      NBT         NetBIOS over TCP/IP disabled on the IP-enabled adapters (informational, not scored)
      AUTORUN     AutoRun disabled on all drive types (NoDriveTypeAutoRun=255)
      SMB_SIGN    SMB server signing required (LanmanServer RequireSecuritySignature=1)
      PSV2        Windows PowerShell 2.0 optional feature not enabled (Win32_OptionalFeature)
      GUEST       Built-in Guest account (RID 501) disabled
      REMOTEREG   Remote Registry service not running
      PS_LOGGING  PowerShell script block logging enabled by policy
    A control that cannot be read (for example without administrator rights) is reported as
    UNKNOWN and left out of the score. Score = passed / (scored controls that could be read).

.PARAMETER MinScorePercent
    Minimum score in percent. Below it the result is FAIL. Default 70.

.PARAMETER Skip
    Control ids to exclude (see the list above), as a list or one comma-separated string.
    Default: none.

.EXAMPLE
    -MinScorePercent 80 -Skip "VBS,PS_LOGGING"

.NOTES
    Name:       Security - Hardening baseline
    GUID:       e1a669f5-3c37-4f56-bb72-1e0ed17de49f
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator recommended; without it some controls may be UNKNOWN)
    Exit codes: 0 OK (all controls pass) | 1 FAIL (score below -MinScorePercent, or error) | 2 WARN (at least one control failed)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MinScorePercent = 70,
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

# Returns the registry value, or $null when the key or the value does not exist.
function Get-RegValue([string]$Path, [string]$Name) {
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

$exitCode = 0
try {
    $allIds = 'UAC', 'LSA_PPL', 'VBS', 'WDIGEST', 'LLMNR', 'NBT', 'AUTORUN', 'SMB_SIGN', 'PSV2', 'GUEST', 'REMOTEREG', 'PS_LOGGING'
    $skipIds = @($Skip | ForEach-Object { [string]$_ -split '[,;\s]+' } | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ })
    foreach ($s in $skipIds) { if ($allIds -notcontains $s) { throw ('unknown control id in -Skip: ' + $s + ' (valid: ' + ($allIds -join ', ') + ')') } }
    if ($MinScorePercent -lt 0 -or $MinScorePercent -gt 100) { throw 'MinScorePercent must be 0-100' }

    $results = New-Object System.Collections.Generic.List[object]
    # Status: PASS, FAIL, UNKNOWN or INFO (INFO = not scored)
    function Add-Result([string]$Id, [string]$Status, [string]$Detail) {
        $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = $Detail }) | Out-Null
    }

    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # UAC
    if ($skipIds -notcontains 'UAC') {
        $lua = Get-RegValue $sysPol 'EnableLUA'
        $cpba = Get-RegValue $sysPol 'ConsentPromptBehaviorAdmin'
        $luaEff = if ($null -eq $lua) { 1 } else { [int]$lua }      # default is enabled
        $cpbaEff = if ($null -eq $cpba) { 5 } else { [int]$cpba }   # default is prompt for consent
        $st = if ($luaEff -eq 1 -and $cpbaEff -ne 0) { 'PASS' } else { 'FAIL' }
        Add-Result 'UAC' $st ('EnableLUA={0} ConsentPromptBehaviorAdmin={1}' -f $luaEff, $cpbaEff)
    }

    # LSA protection
    if ($skipIds -notcontains 'LSA_PPL') {
        $ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
        $pplEff = if ($null -eq $ppl) { 0 } else { [int]$ppl }
        $st = if ($pplEff -eq 1 -or $pplEff -eq 2) { 'PASS' } else { 'FAIL' }
        Add-Result 'LSA_PPL' $st ('RunAsPPL={0}' -f $(if ($null -eq $ppl) { 'not set' } else { $pplEff }))
    }

    # Credential Guard / VBS
    if ($skipIds -notcontains 'VBS') {
        try {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1
            $vbsNames = @{ 0 = 'off'; 1 = 'configured, not running'; 2 = 'running' }
            $vbs = [int]$dg.VirtualizationBasedSecurityStatus
            $vbsText = if ($vbsNames.ContainsKey($vbs)) { $vbsNames[$vbs] } else { [string]$vbs }
            $cg = @($dg.SecurityServicesRunning) -contains [uint32]1
            $st = if ($cg) { 'PASS' } else { 'FAIL' }
            Add-Result 'VBS' $st ('Credential Guard running={0}, VBS {1}' -f $(if ($cg) { 'yes' } else { 'no' }), $vbsText)
        }
        catch { Add-Result 'VBS' 'UNKNOWN' ('Win32_DeviceGuard not readable: ' + $_.Exception.Message) }
    }

    # WDigest
    if ($skipIds -notcontains 'WDIGEST') {
        $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        $st = if ($null -ne $wd -and [int]$wd -eq 1) { 'FAIL' } else { 'PASS' }
        Add-Result 'WDIGEST' $st ('UseLogonCredential={0}' -f $(if ($null -eq $wd) { 'not set' } else { [int]$wd }))
    }

    # LLMNR
    if ($skipIds -notcontains 'LLMNR') {
        $mc = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        $st = if ($null -ne $mc -and [int]$mc -eq 0) { 'PASS' } else { 'FAIL' }
        Add-Result 'LLMNR' $st ('EnableMulticast policy={0}' -f $(if ($null -eq $mc) { 'not set' } else { [int]$mc }))
    }

    # NetBIOS over TCP/IP (informational)
    if ($skipIds -notcontains 'NBT') {
        try {
            $ads = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -Property TcpipNetbiosOptions -ErrorAction Stop)
            $on = @($ads | Where-Object { [int]$_.TcpipNetbiosOptions -ne 2 }).Count
            Add-Result 'NBT' 'INFO' ('{0} of {1} IP adapter(s) with NetBIOS not disabled (default or enabled)' -f $on, $ads.Count)
        }
        catch { Add-Result 'NBT' 'INFO' ('adapters not readable: ' + $_.Exception.Message) }
    }

    # AutoRun
    if ($skipIds -notcontains 'AUTORUN') {
        $ar = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
        $st = if ($null -ne $ar -and [int]$ar -eq 255) { 'PASS' } else { 'FAIL' }
        Add-Result 'AUTORUN' $st ('NoDriveTypeAutoRun={0}' -f $(if ($null -eq $ar) { 'not set' } else { [int]$ar }))
    }

    # SMB server signing
    if ($skipIds -notcontains 'SMB_SIGN') {
        $rs = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
        $st = if ($null -ne $rs -and [int]$rs -eq 1) { 'PASS' } else { 'FAIL' }
        Add-Result 'SMB_SIGN' $st ('server RequireSecuritySignature={0}' -f $(if ($null -eq $rs) { 'not set' } else { [int]$rs }))
    }

    # PowerShell 2.0 feature (InstallState 1 = enabled, 2 = disabled, 3 = absent)
    if ($skipIds -notcontains 'PSV2') {
        try {
            $f = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name = 'MicrosoftWindowsPowerShellV2' OR Name = 'MicrosoftWindowsPowerShellV2Root'" -ErrorAction Stop)
            if ($f.Count -eq 0) { Add-Result 'PSV2' 'PASS' 'feature not present on this Windows' }
            else {
                $enabled = @($f | Where-Object { [int]$_.InstallState -eq 1 })
                $st = if ($enabled.Count) { 'FAIL' } else { 'PASS' }
                Add-Result 'PSV2' $st ('feature {0}' -f $(if ($enabled.Count) { 'enabled' } else { 'disabled' }))
            }
        }
        catch { Add-Result 'PSV2' 'UNKNOWN' ('optional features not readable: ' + $_.Exception.Message) }
    }

    # Guest account (RID 501), found by SID so it works in any language
    if ($skipIds -notcontains 'GUEST') {
        try {
            $guest = $null
            try { $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Select-Object -First 1 }
            catch { Write-Verbose ('Get-LocalUser failed: ' + $_.Exception.Message) }
            if ($guest) {
                $st = if ($guest.Enabled) { 'FAIL' } else { 'PASS' }
                Add-Result 'GUEST' $st ('Guest account {0}' -f $(if ($guest.Enabled) { 'enabled' } else { 'disabled' }))
            }
            else {
                $acc = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = True AND SID LIKE 'S-1-5-21-%-501'" -ErrorAction Stop | Select-Object -First 1
                if ($acc) {
                    $st = if ($acc.Disabled) { 'PASS' } else { 'FAIL' }
                    Add-Result 'GUEST' $st ('Guest account {0}' -f $(if ($acc.Disabled) { 'disabled' } else { 'enabled' }))
                }
                else { Add-Result 'GUEST' 'PASS' 'no Guest account found' }
            }
        }
        catch { Add-Result 'GUEST' 'UNKNOWN' ('local accounts not readable: ' + $_.Exception.Message) }
    }

    # Remote Registry
    if ($skipIds -notcontains 'REMOTEREG') {
        $svc = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if (-not $svc) { Add-Result 'REMOTEREG' 'PASS' 'service not installed' }
        else {
            $st = if ([string]$svc.Status -eq 'Running') { 'FAIL' } else { 'PASS' }
            Add-Result 'REMOTEREG' $st ('service {0}, start {1}' -f $svc.Status, $svc.StartType)
        }
    }

    # Script block logging
    if ($skipIds -notcontains 'PS_LOGGING') {
        $sb = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
        $st = if ($null -ne $sb -and [int]$sb -eq 1) { 'PASS' } else { 'FAIL' }
        Add-Result 'PS_LOGGING' $st ('EnableScriptBlockLogging policy={0}' -f $(if ($null -eq $sb) { 'not set' } else { [int]$sb }))
    }

    $scored = @($results | Where-Object { $_.Status -eq 'PASS' -or $_.Status -eq 'FAIL' })
    $passed = @($scored | Where-Object { $_.Status -eq 'PASS' }).Count
    $failed = @($scored | Where-Object { $_.Status -eq 'FAIL' })
    $total = $scored.Count
    $pct = if ($total) { [math]::Floor(100 * $passed / $total) } else { 0 }

    if ($total -eq 0) {
        Write-Line 'FAIL: no hardening control could be evaluated'
        $exitCode = 1
    }
    elseif ($pct -lt $MinScorePercent) {
        Write-Line ('FAIL: hardening score {0}% below {1}% ({2}/{3}); failed: {4}' -f $pct, $MinScorePercent, $passed, $total, (($failed | ForEach-Object { $_.Id }) -join ', '))
        $exitCode = 1
    }
    elseif ($failed.Count) {
        Write-Line ('WARN: hardening score {0}% ({1}/{2}); failed: {3}' -f $pct, $passed, $total, (($failed | ForEach-Object { $_.Id }) -join ', '))
        $exitCode = 2
    }
    else {
        Write-Line ('OK: all {0} hardening controls pass' -f $total)
    }
    Write-Line ('INFO: Score: {0}/{1}' -f $passed, $total)
    foreach ($r in $results) { Write-Line ('INFO: {0} {1} - {2}' -f $r.Status, $r.Id, $r.Detail) }
    if ($skipIds.Count) { Write-Line ('INFO: skipped: ' + ($skipIds -join ', ')) }
}
catch {
    Write-Line ('FAIL: could not evaluate the hardening baseline: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
