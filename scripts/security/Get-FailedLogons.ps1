#Requires -Version 5.1
<#
.SYNOPSIS
    Counts failed logons (event 4625) and account lockouts (event 4740) in the last hours.

.DESCRIPTION
    Reads the Security event log with Get-WinEvent -FilterHashtable (filtered by the event log
    service, fast) and groups the failed logons by target account, by source network address,
    by logon type and by failure sub-status. At most 5000 events of each id are read; when the
    cap is reached the counts are "at least". Account lockouts (4740) are counted and grouped
    by account. Read-only.
    Use it as a check for password spraying / brute force: the total count of failed logons is
    compared with -WarnThreshold and -FailThreshold.
    Note: failed logons are only logged when the "Logon" audit subcategory records failures
    (default on Windows workstations and servers).
    Reading the Security log requires administrator or SYSTEM; when the log cannot be read the
    script exits 3 (not applicable) with a clear message instead of reporting a false OK.

.PARAMETER Hours
    Time window in hours. Default 24.

.PARAMETER WarnThreshold
    WARN when the number of failed logons is at least this value. Default 20.

.PARAMETER FailThreshold
    FAIL when the number of failed logons is at least this value. Default 100.

.EXAMPLE
    -Hours 1 -WarnThreshold 10 -FailThreshold 50

.NOTES
    Name:       Security - Failed logons
    GUID:       2daa3881-cae8-4353-9001-d76d565d71d8
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator required to read the Security log)
    Exit codes: 0 OK | 1 FAIL (count >= -FailThreshold, or error) | 2 WARN (count >= -WarnThreshold) | 3 NOT APPLICABLE (Security log not readable)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$WarnThreshold = 20,
    [int]$FailThreshold = 100
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

$maxEvents = 5000

# Returns the events, an empty array when none match, or throws 'NOT_READABLE: ...'.
function Get-SecurityEvent([int]$Id, [datetime]$Since) {
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Id; StartTime = $Since } -MaxEvents $maxEvents -ErrorAction Stop)
    }
    catch {
        $fq = [string]$_.FullyQualifiedErrorId
        if ($fq -like 'NoMatchingEventsFound*') { return @() }
        $inner = $_.Exception.InnerException
        if ($fq -like 'LogInfoUnavailable*' -or $_.Exception -is [System.UnauthorizedAccessException] -or $inner -is [System.UnauthorizedAccessException]) {
            throw ('NOT_READABLE: ' + $_.Exception.Message)
        }
        throw
    }
}

$logonTypes = @{ 2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Unlock'; 8 = 'NetworkCleartext'; 9 = 'NewCredentials'; 10 = 'RemoteInteractive'; 11 = 'CachedInteractive' }
$subStatus = @{
    '0xc000006a' = 'bad password'; '0xc0000064' = 'unknown user'; '0xc0000234' = 'account locked'
    '0xc0000072' = 'account disabled'; '0xc000006f' = 'outside logon hours'; '0xc0000070' = 'workstation restriction'
    '0xc0000071' = 'password expired'; '0xc0000193' = 'account expired'; '0xc0000224' = 'password must change'
    '0xc000015b' = 'logon type not granted'; '0xc000006d' = 'bad user name or password'; '0xc0000133' = 'clock skew'
}

function Write-Top([string]$Title, [hashtable]$Table, [int]$Top) {
    if ($Table.Count -eq 0) { return }
    $parts = $Table.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $Top |
        ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value }
    Write-Line ('INFO: {0}: {1}' -f $Title, ($parts -join ', '))
}

$exitCode = 0
try {
    if ($Hours -lt 1) { throw 'Hours must be at least 1' }
    $since = (Get-Date).AddHours(-$Hours)

    $failed = Get-SecurityEvent 4625 $since
    $locks = Get-SecurityEvent 4740 $since

    $byAccount = @{}; $bySource = @{}; $byType = @{}; $byReason = @{}; $lockAccounts = @{}
    foreach ($e in $failed) {
        $p = $e.Properties
        # 4625 fields: 5 TargetUserName, 6 TargetDomainName, 9 SubStatus, 10 LogonType, 13 WorkstationName, 19 IpAddress
        $user = [string]$p[5].Value
        $dom = [string]$p[6].Value
        $acct = Limit-Text $(if ($dom -and $dom -ne '-') { $dom + '\' + $user } else { $user }) 40
        if (-not $acct) { $acct = '(empty)' }
        $byAccount[$acct] = 1 + [int]$byAccount[$acct]

        $ip = [string]$p[19].Value
        if (-not $ip -or $ip -eq '-') { $ip = 'local' }
        $ws = [string]$p[13].Value
        if ($ws -and $ws -ne '-' -and $ip -ne 'local') { $ip = $ip + ' (' + (Limit-Text $ws 20) + ')' }
        $bySource[$ip] = 1 + [int]$bySource[$ip]

        $lt = 0
        [void][int]::TryParse([string]$p[10].Value, [ref]$lt)
        $ltName = if ($logonTypes.ContainsKey($lt)) { '{0} {1}' -f $lt, $logonTypes[$lt] } else { [string]$lt }
        $byType[$ltName] = 1 + [int]$byType[$ltName]

        $ss = ('0x{0:x8}' -f [uint32]$p[9].Value)
        $reason = if ($subStatus.ContainsKey($ss)) { $subStatus[$ss] } else { $ss }
        $byReason[$reason] = 1 + [int]$byReason[$reason]
    }
    foreach ($e in $locks) {
        # 4740 fields: 0 TargetUserName, 1 caller computer
        $u = Limit-Text ([string]$e.Properties[0].Value) 40
        $lockAccounts[$u] = 1 + [int]$lockAccounts[$u]
    }

    $count = $failed.Count
    $atLeast = if ($count -ge $maxEvents) { 'at least ' } else { '' }
    $lockText = '{0}{1} lockout(s)' -f $(if ($locks.Count -ge $maxEvents) { 'at least ' } else { '' }), $locks.Count
    $summary = '{0}{1} failed logon(s) and {2} in the last {3} h' -f $atLeast, $count, $lockText, $Hours

    if ($count -ge $FailThreshold) {
        Write-Line ('FAIL: {0} (fail threshold {1})' -f $summary, $FailThreshold); $exitCode = 1
    }
    elseif ($count -ge $WarnThreshold) {
        Write-Line ('WARN: {0} (warn threshold {1})' -f $summary, $WarnThreshold); $exitCode = 2
    }
    else {
        Write-Line ('OK: {0}' -f $summary)
    }
    Write-Top 'top accounts' $byAccount 10
    Write-Top 'top sources' $bySource 10
    Write-Top 'logon types' $byType 6
    Write-Top 'reasons' $byReason 6
    Write-Top 'locked accounts' $lockAccounts 10
    if ($count) {
        $first = ($failed | Select-Object -Last 1).TimeCreated
        $last = ($failed | Select-Object -First 1).TimeCreated
        Write-Line ('INFO: first {0:yyyy-MM-dd HH:mm}, last {1:yyyy-MM-dd HH:mm}' -f $first, $last)
    }
}
catch {
    $msg = $_.Exception.Message
    if ($msg -like 'NOT_READABLE:*') {
        Write-Line ('INFO: Security log not readable; this check requires administrator or SYSTEM. ' + $msg.Substring(13).Trim())
        $exitCode = 3
    }
    else {
        Write-Line ('FAIL: could not read failed logons: ' + $msg)
        $exitCode = 1
    }
}
$host.SetShouldExit($exitCode); exit $exitCode
