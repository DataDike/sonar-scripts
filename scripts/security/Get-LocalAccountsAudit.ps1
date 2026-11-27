#Requires -Version 5.1
<#
.SYNOPSIS
    Audits local user accounts: enabled, last logon, password age and flags, administrator membership.

.DESCRIPTION
    Lists every local user (Get-LocalUser) with: enabled state, last logon, password last set,
    password never expires, password required and membership of the local Administrators group
    (well-known SID S-1-5-32-544, so any display language works). The password flags are read
    from Win32_UserAccount (local accounts only, one query). The built-in Administrator
    (RID 500) and Guest (RID 501) accounts are labelled. Read-only.
    For ENABLED accounts:
      FAIL  password not required (the account may have an empty password)
      WARN  password never expires, password older than -MaxPasswordAgeDays, or no logon in
            -MaxInactiveDays (or never logged on)
    Disabled accounts are listed for information only.

.PARAMETER MaxPasswordAgeDays
    WARN when the password of an enabled account is older than this. Default 365.

.PARAMETER MaxInactiveDays
    WARN when an enabled account has not logged on for this many days. Default 90.

.EXAMPLE
    -MaxPasswordAgeDays 180 -MaxInactiveDays 60

.NOTES
    Name:       Security - Local accounts
    GUID:       c1fb9eba-e133-4be4-b828-445d596c49a9
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator not required)
    Exit codes: 0 OK | 1 FAIL (enabled account without required password, or error) | 2 WARN (password or inactivity finding) | 3 NOT APPLICABLE (domain controller)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxPasswordAgeDays = 365,
    [int]$MaxInactiveDays = 90
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
    # Domain controllers have no local SAM accounts
    $role = [int](Get-CimInstance -ClassName Win32_ComputerSystem -Property DomainRole -ErrorAction Stop).DomainRole
    if ($role -ge 4) {
        Write-Line 'INFO: domain controller, no local accounts to audit'
        $host.SetShouldExit(3); exit 3
    }
    $users = @(Get-LocalUser -ErrorAction Stop)
    $now = Get-Date

    # Local Administrators members (SIDs)
    $adminSids = @{}
    $adminNote = $null
    try {
        foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) { $adminSids[[string]$m.SID.Value] = $true }
    }
    catch {
        try {
            $gName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
            $group = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME, $gName)
            foreach ($raw in @($group.psbase.Invoke('Members'))) {
                $entry = [ADSI]$raw
                $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$entry.InvokeGet('objectSid'), 0)).Value
                $adminSids[$sid] = $true
            }
        }
        catch { $adminNote = 'Administrators membership not readable: ' + $_.Exception.Message }
    }

    # Password flags of all local accounts in one query (per-account ADSI binding can be very slow)
    $flagsBySid = @{}
    try {
        foreach ($acc in @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = True' -Property SID, PasswordExpires, PasswordRequired -ErrorAction Stop)) {
            $flagsBySid[[string]$acc.SID] = $acc
        }
    }
    catch { Write-Verbose ('Win32_UserAccount not readable: ' + $_.Exception.Message) }

    $fails = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($u in ($users | Sort-Object -Property @{ Expression = { -not $_.Enabled } }, Name)) {
        $sid = [string]$u.SID.Value
        $label = ''
        if ($sid -like 'S-1-5-21-*-500') { $label = ' [built-in Administrator]' }
        elseif ($sid -like 'S-1-5-21-*-501') { $label = ' [built-in Guest]' }

        # Flags from Win32_UserAccount (SAM); fall back to Get-LocalUser properties
        $neverExpires = $null
        $pwdRequired = [bool]$u.PasswordRequired
        if ($flagsBySid.ContainsKey($sid)) {
            $neverExpires = -not [bool]$flagsBySid[$sid].PasswordExpires
            $pwdRequired = [bool]$flagsBySid[$sid].PasswordRequired
        }
        if ($null -eq $neverExpires) { $neverExpires = ($null -eq $u.PasswordExpires -and $null -ne $u.PasswordLastSet) }

        $isAdmin = $adminSids.ContainsKey($sid)
        $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd') } else { 'never' }
        $pwdAge = if ($u.PasswordLastSet) { [int]($now - $u.PasswordLastSet).TotalDays } else { $null }
        $pwdText = if ($null -ne $pwdAge) { '{0} d ago' -f $pwdAge } else { 'never' }

        $issues = New-Object System.Collections.Generic.List[string]
        if ($u.Enabled) {
            $name = [string]$u.Name
            if (-not $pwdRequired) { $issues.Add('password not required') | Out-Null; $fails.Add($name + ': password not required') | Out-Null }
            if ($neverExpires) { $issues.Add('password never expires') | Out-Null; $warns.Add($name + ': password never expires') | Out-Null }
            if ($null -ne $pwdAge -and $pwdAge -gt $MaxPasswordAgeDays) { $issues.Add('password older than ' + $MaxPasswordAgeDays + ' d') | Out-Null; $warns.Add($name + ': password ' + $pwdAge + ' d old') | Out-Null }
            if (-not $u.LastLogon) { $issues.Add('never logged on') | Out-Null; $warns.Add($name + ': never logged on') | Out-Null }
            elseif (($now - $u.LastLogon).TotalDays -gt $MaxInactiveDays) { $issues.Add('inactive more than ' + $MaxInactiveDays + ' d') | Out-Null; $warns.Add($name + ': inactive since ' + $lastLogon) | Out-Null }
        }
        $lines.Add(('INFO: {0}{1} | {2} | admin={3} | last logon {4} | password set {5} | never expires={6} | required={7}{8}' -f
                $u.Name, $label, $(if ($u.Enabled) { 'enabled' } else { 'disabled' }), $(if ($isAdmin) { 'yes' } else { 'no' }),
                $lastLogon, $pwdText, $(if ($neverExpires) { 'yes' } else { 'no' }), $(if ($pwdRequired) { 'yes' } else { 'no' }),
                $(if ($issues.Count) { ' | ' + ($issues -join ', ') } else { '' }))) | Out-Null
    }

    $enabledCount = @($users | Where-Object { $_.Enabled }).Count
    if ($fails.Count) {
        Write-Line ('FAIL: {0} enabled local account(s) without required password: {1}' -f $fails.Count, (($fails | ForEach-Object { $_.Split(':')[0] }) -join ', '))
        $exitCode = 1
    }
    elseif ($warns.Count) {
        Write-Line ('WARN: {0} finding(s) on enabled local accounts: {1}' -f $warns.Count, ((@($warns) | Select-Object -First 10) -join '; '))
        $exitCode = 2
    }
    else {
        Write-Line ('OK: {0} local account(s), {1} enabled, no findings' -f $users.Count, $enabledCount)
    }
    if ($fails.Count -and $warns.Count) { Write-Line ('WARN: also ' + ((@($warns) | Select-Object -First 10) -join '; ')) }
    $n = 0
    foreach ($l in $lines) {
        if ($n -ge 25) { Write-Line ('INFO: {0} more account(s) not shown' -f ($lines.Count - $n)); break }
        Write-Line $l
        $n++
    }
    if ($adminNote) { Write-Line ('INFO: ' + $adminNote) }
}
catch {
    Write-Line ('FAIL: could not read local accounts: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
