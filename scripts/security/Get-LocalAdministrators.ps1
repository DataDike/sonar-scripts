#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the members of the local Administrators group and optionally fails on unexpected members.

.DESCRIPTION
    Finds the local Administrators group by its well-known SID S-1-5-32-544, so it works on any
    Windows display language. Members are read with Get-LocalGroupMember; when that fails (known
    bug with orphaned SIDs, or the cmdlet is missing) the script falls back to ADSI (WinNT provider).
    Each member is printed with its type (User/Group) and source (Local, Domain, AzureAD,
    MicrosoftAccount or Unknown SID). The built-in Administrator account (SID ending in -500) is
    always listed with its enabled state and is always accepted.
    With -Allowed the script works as a check: it fails when a member matches none of the patterns.
    Read-only.

.PARAMETER Allowed
    Names or wildcard patterns of accepted members, matched against "DOMAIN\Name", the bare name
    and the SID (for example "*\Domain Admins", "*\Administrator", "S-1-12-1-*"), as a list or one
    comma-separated string. Default: none, which only lists the members.

.EXAMPLE
    -Allowed "*\Domain Admins","*\Administrator"

.NOTES
    Name:       Security - Local administrators
    GUID:       a9f8d3d0-f497-4810-ac62-78ab4d7d18d3
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (member not in -Allowed, or error)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string[]]$Allowed = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

$groupSid = 'S-1-5-32-544'

function Get-MachineSid {
    try {
        $u = Get-LocalUser -ErrorAction Stop | Select-Object -First 1
        if ($u) { return $u.SID.AccountDomainSid.Value }
    }
    catch { Write-Verbose ('Get-LocalUser failed: ' + $_.Exception.Message) }
    try {
        $acc = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = True' -Property SID -ErrorAction Stop | Select-Object -First 1
        if ($acc) { return (New-Object System.Security.Principal.SecurityIdentifier($acc.SID)).AccountDomainSid.Value }
    }
    catch { Write-Verbose ('Win32_UserAccount failed: ' + $_.Exception.Message) }
    return $null
}

function Get-SourceFromSid([string]$Sid, [string]$MachineSid, [bool]$Resolved) {
    if (-not $Resolved) { return 'Unknown SID' }
    if ($Sid -like 'S-1-12-1-*') { return 'AzureAD' }
    if ($MachineSid -and $Sid.StartsWith($MachineSid + '-')) { return 'Local' }
    if ($Sid -like 'S-1-5-21-*') { return 'Domain' }
    return 'Local'
}

$exitCode = 0
try {
    # Normalize -Allowed: a list, or one "a,b" string when passed through -File
    $Allowed = @($Allowed | ForEach-Object { [string]$_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $machineSid = Get-MachineSid
    $members = New-Object System.Collections.Generic.List[object]
    $method = 'Get-LocalGroupMember'

    # ADSI (WinNT) view: language-neutral class names, and the fallback when Get-LocalGroupMember fails
    $adsi = New-Object System.Collections.Generic.List[object]
    $adsiError = $null
    try {
        $groupName = (New-Object System.Security.Principal.SecurityIdentifier($groupSid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $groupName)
        foreach ($raw in @($group.psbase.Invoke('Members'))) {
            $entry = [ADSI]$raw
            $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$entry.InvokeGet('objectSid'), 0)).Value
            $cls = [string]$entry.InvokeGet('Class')
            $resolved = $true
            try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $resolved = $false; $name = $sid }
            $type = if ($cls -match '(?i)group') { 'Group' } elseif ($cls -match '(?i)user') { 'User' } else { $cls }
            $adsi.Add([pscustomobject]@{ Name = $name; Sid = $sid; Type = $type; Source = (Get-SourceFromSid $sid $machineSid $resolved) }) | Out-Null
        }
    }
    catch { $adsiError = $_.Exception.Message }
    $typeBySid = @{}
    foreach ($a in $adsi) { $typeBySid[$a.Sid] = $a.Type }

    try {
        foreach ($m in @(Get-LocalGroupMember -SID $groupSid -ErrorAction Stop)) {
            $sid = [string]$m.SID.Value
            $src = [string]$m.PrincipalSource
            if ($src -eq 'ActiveDirectory') { $src = 'Domain' }
            if (-not $src -or $src -eq 'Unknown') { $src = Get-SourceFromSid $sid $machineSid $true }
            # ObjectClass is localized ("Usuario", "Benutzer"...): prefer the ADSI class
            $type = [string]$m.ObjectClass
            if ($typeBySid.ContainsKey($sid)) { $type = $typeBySid[$sid] }
            elseif ($type -match '(?i)group|grupo|gruppe|groupe') { $type = 'Group' }
            else { $type = 'User' }
            $members.Add([pscustomobject]@{ Name = [string]$m.Name; Sid = $sid; Type = $type; Source = $src }) | Out-Null
        }
    }
    catch {
        if ($adsiError) { throw ('Get-LocalGroupMember failed (' + $_.Exception.Message + ') and ADSI failed (' + $adsiError + ')') }
        $method = 'ADSI (Get-LocalGroupMember failed: ' + $_.Exception.Message + ')'
        $members = $adsi
    }

    # Built-in Administrator (-500): always listed, always accepted
    $builtinLine = $null
    if ($machineSid) {
        $bSid = $machineSid + '-500'
        $state = 'unknown'
        try {
            $bu = Get-LocalUser -SID $bSid -ErrorAction Stop
            $state = if ($bu.Enabled) { 'enabled' } else { 'disabled' }
            $bName = $env:COMPUTERNAME + '\' + $bu.Name
        }
        catch { $bName = $bSid }
        $isMember = @($members | Where-Object { $_.Sid -eq $bSid }).Count -gt 0
        $builtinLine = 'INFO: built-in Administrator {0} ({1}, {2})' -f $bName, $state, $(if ($isMember) { 'member' } else { 'not a member' })
    }

    # Evaluate against -Allowed
    $notAllowed = New-Object System.Collections.Generic.List[string]
    if ($Allowed.Count) {
        foreach ($m in $members) {
            if ($m.Sid -like '*-500' -and $machineSid -and $m.Sid -eq ($machineSid + '-500')) { continue }
            $short = $m.Name.Split('\')[-1]
            $ok = $false
            foreach ($pattern in $Allowed) {
                if ($m.Name -like $pattern -or $short -like $pattern -or $m.Sid -like $pattern) { $ok = $true; break }
            }
            if (-not $ok) { $notAllowed.Add($m.Name) | Out-Null }
        }
    }

    if ($notAllowed.Count) {
        Write-Line ('FAIL: {0} member(s) of local Administrators not allowed: {1}' -f $notAllowed.Count, ($notAllowed -join ', '))
        $exitCode = 1
    }
    elseif ($Allowed.Count) {
        Write-Line ('OK: all {0} member(s) of local Administrators are allowed' -f $members.Count)
    }
    else {
        Write-Line ('OK: {0} member(s) in local Administrators' -f $members.Count)
    }

    $n = 0
    foreach ($m in ($members | Sort-Object -Property Name)) {
        if ($n -ge 40) { Write-Line ('INFO: {0} more member(s) not shown' -f ($members.Count - $n)); break }
        Write-Line ('INFO: {0} | {1} | {2}' -f $m.Name, $m.Type, $m.Source)
        $n++
    }
    if ($builtinLine) { Write-Line $builtinLine }
    Write-Line ('INFO: read with ' + $method)
}
catch {
    Write-Line ('FAIL: could not read local Administrators: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
