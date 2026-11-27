#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the users logged on interactively (console and remote desktop) with state and idle time.

.DESCRIPTION
    Reads the sessions with quser (user, session name, id, state Active/Disconnected, idle time,
    logon time). quser headers and states are localized, so lines are parsed by shape, not by
    column title. When quser is missing or its output cannot be parsed, falls back to
    Win32_LogonSession + Win32_LoggedOnUser (logon types 2 interactive, 10 remote desktop,
    11 cached; this view has no state or idle time and may keep sessions that already ended).
    The console user comes from Win32_ComputerSystem.UserName.
    Inventory action, read-only. Always exits 0 when it runs: the first line is
    "INFO: no interactive user logged on" when nobody is logged on.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Inventory - Logged-on users
    GUID:       01ac77fd-4c67-4b37-b3a1-f7c487565f19
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); any user can list sessions
    Exit codes: 0 OK (also when nobody is logged on) | 1 FAIL (error)
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

function Test-AccessDenied($ErrorRecord) {
    return ([string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied|0x80070005')
}

# Localized session states (English, Portuguese, Spanish, German, French, Italian)
function Get-StateName([string]$State) {
    $s = ConvertTo-AsciiText $State
    if ($s -match '(?i)^(activ|ativ|aktiv|attiv)') { return 'Active' }
    if ($s -match '(?i)^(disc|desc|getr|deco|disco)') { return 'Disconnected' }
    return $s
}

# quser line: [>]user [session] id state idle logon-time (session is empty for disconnected sessions)
$lineRegex = '^\s*>?(?<user>\S+)\s+(?:(?<session>\S+)\s+)?(?<id>\d+)\s+(?<state>\S+)\s+(?<idle>\S+)\s+(?<logon>\S.*?)\s*$'

function Get-QuserSession {
    $exe = Join-Path $env:SystemRoot 'System32\quser.exe'
    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $env:SystemRoot 'Sysnative\quser.exe' }
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $raw = @(& $exe 2>$null) }
    finally { $ErrorActionPreference = $old }
    $lines = @($raw | Where-Object { $_ -and ([string]$_).Trim() })
    if ($lines.Count -lt 2) { return , @() }   # header only, or nothing ("no user" goes to stderr)
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($l in ($lines | Select-Object -Skip 1)) {
        $m = [regex]::Match([string]$l, $lineRegex)
        if (-not $m.Success) { return $null }
        $idle = $m.Groups['idle'].Value
        if ($idle -notmatch '^\d') { $idle = 'none' }
        $result.Add([pscustomobject]@{
            User    = ConvertTo-AsciiText $m.Groups['user'].Value
            Session = $(if ($m.Groups['session'].Success) { ConvertTo-AsciiText $m.Groups['session'].Value } else { '-' })
            Id      = [int]$m.Groups['id'].Value
            State   = Get-StateName $m.Groups['state'].Value
            Idle    = $idle
            Logon   = ConvertTo-AsciiText $m.Groups['logon'].Value
        }) | Out-Null
    }
    return , $result.ToArray()
}

function Get-CimLogonSession {
    $types = @{ 2 = 'interactive'; 10 = 'remote desktop'; 11 = 'cached interactive' }
    $sessions = @{}
    foreach ($s in @(Get-CimInstance -ClassName Win32_LogonSession -Filter 'LogonType = 2 OR LogonType = 10 OR LogonType = 11' -ErrorAction Stop)) {
        $sessions[[string]$s.LogonId] = $s
    }
    $result = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($link in @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop)) {
        $id = [string]$link.Dependent.LogonId
        if (-not $sessions.ContainsKey($id)) { continue }
        $domain = [string]$link.Antecedent.Domain
        $name = [string]$link.Antecedent.Name
        if ($name -match '^(DWM|UMFD)-\d+$') { continue }   # desktop window manager / font driver accounts
        $s = $sessions[$id]
        $key = ($domain + '\' + $name + '|' + [string]$s.LogonType).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $result.Add([pscustomobject]@{
            User    = ConvertTo-AsciiText ($domain + '\' + $name)
            Session = $types[[int]$s.LogonType]
            Id      = $id
            State   = '?'
            Idle    = '?'
            Logon   = $(if ($s.StartTime) { $s.StartTime.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) } else { '?' })
        }) | Out-Null
    }
    return , $result.ToArray()
}

$exitCode = 0
try {
    $console = $null
    try { $console = [string](Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName -ErrorAction Stop).UserName }
    catch { Write-Verbose ('Win32_ComputerSystem: ' + $_.Exception.Message) }

    $method = 'quser'
    $note = $null
    $sessions = Get-QuserSession
    if ($null -eq $sessions) {
        $method = 'Win32_LogonSession (quser not available or not parsable)'
        $note = 'INFO: no state or idle time in this view; ended sessions may still be listed'
        try { $sessions = Get-CimLogonSession }
        catch {
            if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading logon sessions (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
            throw
        }
    }
    $sessions = @($sessions)

    $consoleText = if ($console) { ConvertTo-AsciiText $console } else { 'none' }
    if (-not $sessions.Count -and -not $console) {
        Write-Output 'INFO: no interactive user logged on'
        Write-Output ('INFO: read with ' + $method)
        $host.SetShouldExit(0); exit 0
    }
    $active = @($sessions | Where-Object { $_.State -eq 'Active' }).Count
    $disc = @($sessions | Where-Object { $_.State -eq 'Disconnected' }).Count
    if ($method -eq 'quser') {
        Write-Output ('OK: {0} interactive session(s), {1} active, {2} disconnected; console user {3}' -f $sessions.Count, $active, $disc, $consoleText)
    }
    else {
        Write-Output ('OK: {0} interactive logon session(s); console user {1}' -f $sessions.Count, $consoleText)
    }

    $budget = 3600
    $printed = 0
    foreach ($s in $sessions) {
        $line = ConvertTo-AsciiText ('INFO: {0} | session {1} (id {2}) | {3} | idle {4} | logon {5}' -f $s.User, $s.Session, $s.Id, $s.State, $s.Idle, $s.Logon)
        if (($budget - ($line.Length + 2)) -lt 0) { break }
        $budget -= ($line.Length + 2)
        Write-Output $line
        $printed++
    }
    if ($printed -lt $sessions.Count) { Write-Output ('INFO: {0} more not shown' -f ($sessions.Count - $printed)) }
    if ($note) { Write-Output $note }
    Write-Output ('INFO: read with ' + $method)
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading sessions (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not list logged-on users: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
