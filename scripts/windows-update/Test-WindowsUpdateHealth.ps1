#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the local health of the Windows Update client.

.DESCRIPTION
    Read-only check. It reads:
      - the services wuauserv, BITS, cryptsvc and TrustedInstaller (present, start type not Disabled);
      - the last successful scan and the last successful install, from the Windows Update Agent
        (Microsoft.Update.AutoUpdate COM object), with registry and update history fallbacks;
        any update counts here, definition updates included (use 'Windows Update - Last install
        age' to track operating system updates); dates in the future are ignored;
      - the size of the SoftwareDistribution folder;
      - the pending reboot flags (Windows Update, servicing stack, pending file renames);
      - whether a WSUS server is configured by policy (only yes/no; the server address is never printed).
    It never contacts the update service and never changes anything.

    Verdict rules:
      FAIL (1) a required service is missing or Disabled, or the check itself failed.
      WARN (2) last successful scan older than -MaxScanAgeDays or unknown,
               last successful install older than -MaxInstallAgeDays or unknown,
               SoftwareDistribution larger than -MaxFolderSizeGB,
               or a reboot is pending.
      OK   (0) none of the above.
    Use it as a script check (configure 2 as warning) or run it on demand.

.PARAMETER MaxScanAgeDays
    Days since the last successful update scan before a warning. Default 7.

.PARAMETER MaxInstallAgeDays
    Days since the last successful update install before a warning. Default 45.

.PARAMETER MaxFolderSizeGB
    Size of the SoftwareDistribution folder, in GB, before a warning. Default 10.

.EXAMPLE
    -MaxScanAgeDays 3 -MaxInstallAgeDays 35

.NOTES
    Name:       Windows Update - Health check
    GUID:       ba9b9aad-1b25-48c5-b417-441b6ab6846e
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); works with reduced detail as a standard user
    Exit codes: 0 OK | 1 FAIL | 2 WARN
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxScanAgeDays = 7,
    [int]$MaxInstallAgeDays = 45,
    [double]$MaxFolderSizeGB = 10
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$lines = New-Object System.Collections.Generic.List[string]
$script:isFail = $false
$script:isWarn = $false
$script:futureDates = 0
function Add-Fail([string]$msg) { $script:isFail = $true; $lines.Add('FAIL: ' + $msg) }
function Add-Warn([string]$msg) { $script:isWarn = $true; $lines.Add('WARN: ' + $msg) }
function Add-Ok([string]$msg) { $lines.Add('OK: ' + $msg) }
function Add-Info([string]$msg) { $lines.Add('INFO: ' + $msg) }

# Returns a UTC DateTime or $null when the value means "never".
function ConvertTo-ValidUtc($value) {
    if ($null -eq $value) { return $null }
    try { $d = [datetime]$value } catch { return $null }
    if ($d.Year -lt 2000) { return $null }
    # a date in the future comes from a corrupted history entry or a wrong clock: ignore it
    if ($d -gt [datetime]::UtcNow.AddDays(1)) { $script:futureDates++; return $null }
    return $d
}

function Get-RegistryResultTime([string]$subKey) {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\' + $subKey
    try {
        $v = (Get-ItemProperty -Path $path -Name 'LastSuccessTime' -ErrorAction Stop).LastSuccessTime
        $d = [datetime]::ParseExact([string]$v, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        return $d
    } catch { return $null }
}

function Test-AgeRule([string]$label, $utcDate, [int]$maxDays, [string]$source) {
    if ($null -eq $utcDate) {
        Add-Warn ("last successful {0}: unknown or never" -f $label)
        return
    }
    $age = [math]::Floor(([datetime]::UtcNow - $utcDate).TotalDays)
    $text = "last successful {0}: {1} UTC ({2} days ago, source {3})" -f $label, $utcDate.ToString('yyyy-MM-dd HH:mm'), $age, $source
    if ($age -gt $maxDays) { Add-Warn ($text + ", limit $maxDays") } else { Add-Ok $text }
}

$exitCode = 0
try {
    # 1. Services
    $wanted = 'wuauserv', 'BITS', 'cryptsvc', 'TrustedInstaller'
    $filter = ($wanted | ForEach-Object { "Name='$_'" }) -join ' OR '
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter $filter)
    foreach ($name in $wanted) {
        $svc = $services | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $svc) { Add-Fail "service $name is missing"; continue }
        if ($svc.StartMode -eq 'Disabled') { Add-Fail ("service {0} is Disabled (state {1})" -f $name, $svc.State) }
        else { Add-Ok ("service {0}: start {1}, state {2}" -f $name, $svc.StartMode, $svc.State) }
    }

    # 2. Last scan / install
    $scanUtc = $null; $installUtc = $null; $source = 'agent'
    try {
        $au = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
        $results = $au.Results
        $scanUtc = ConvertTo-ValidUtc $results.LastSearchSuccessDate
        $installUtc = ConvertTo-ValidUtc $results.LastInstallationSuccessDate
    } catch {
        $source = 'registry'
        Add-Info ("update agent COM object unavailable: " + $_.Exception.Message.Trim())
    }
    $scanSource = $source; $installSource = $source
    if ($null -eq $scanUtc) { $r = Get-RegistryResultTime 'Detect'; if ($r) { $scanUtc = $r; $scanSource = 'registry' } }
    if ($null -eq $installUtc) { $r = Get-RegistryResultTime 'Install'; if ($r) { $installUtc = $r; $installSource = 'registry' } }
    if ($null -eq $installUtc) {
        # last resort: newest successful install in the agent history (Operation 1, ResultCode 2 or 3)
        try {
            $searcher = (New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateSearcher()
            $count = $searcher.GetTotalHistoryCount()
            if ($count -gt 0) {
                foreach ($h in $searcher.QueryHistory(0, [math]::Min($count, 100))) {
                    if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
                    $d = ConvertTo-ValidUtc $h.Date
                    if ($d -and ($null -eq $installUtc -or $d -gt $installUtc)) { $installUtc = $d; $installSource = 'history' }
                }
            }
        } catch { $null = $_ }
    }
    if ($script:futureDates -gt 0) { Add-Info 'a date in the future was reported by the update agent and ignored' }
    Test-AgeRule 'scan' $scanUtc $MaxScanAgeDays $scanSource
    Test-AgeRule 'install' $installUtc $MaxInstallAgeDays $installSource

    # 3. SoftwareDistribution size
    $sd = Join-Path $env:SystemRoot 'SoftwareDistribution'
    if (Test-Path -LiteralPath $sd) {
        $errs = $null
        $sum = (Get-ChildItem -LiteralPath $sd -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable errs |
                Measure-Object -Property Length -Sum).Sum
        if ($null -eq $sum) { $sum = 0 }
        $gb = [math]::Round($sum / 1GB, 2)
        $partial = ''
        if ($errs -and @($errs).Count -gt 0) { $partial = (' (partial: {0} item(s) not readable)' -f @($errs).Count) }
        if ($gb -gt $MaxFolderSizeGB) { Add-Warn ("SoftwareDistribution size {0} GB, limit {1} GB{2}" -f $gb, $MaxFolderSizeGB, $partial) }
        else { Add-Ok ("SoftwareDistribution size {0} GB{1}" -f $gb, $partial) }
    } else {
        Add-Info 'SoftwareDistribution folder not found (it is recreated by the update service)'
    }

    # 4. Pending reboot
    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('Windows Update') }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('component servicing') }
    try {
        $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) { $reasons.Add('pending file renames') }
    } catch { $null = $_ }
    if ($reasons.Count -gt 0) { Add-Warn ('reboot pending: ' + ($reasons -join ', ')) } else { Add-Ok 'no reboot pending' }

    # 5. WSUS by policy (never print the server address)
    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $hasServer = $false; $useServer = $false
    try { $hasServer = [bool](Get-ItemProperty -Path $wuPol -Name 'WUServer' -ErrorAction Stop).WUServer } catch { $null = $_ }
    try { $useServer = ((Get-ItemProperty -Path ($wuPol + '\AU') -Name 'UseWUServer' -ErrorAction Stop).UseWUServer -eq 1) } catch { $null = $_ }
    if ($hasServer -and $useServer) { Add-Info 'WSUS server configured by policy and in use' }
    elseif ($hasServer) { Add-Info 'WSUS server set by policy but UseWUServer is not 1 (not in use)' }
    else { Add-Info 'no WSUS server configured by policy' }

    if ($script:isFail) { $exitCode = 1; $verdict = 'FAIL: Windows Update client has problems' }
    elseif ($script:isWarn) { $exitCode = 2; $verdict = 'WARN: Windows Update client needs attention' }
    else { $verdict = 'OK: Windows Update client looks healthy' }
    Write-Output $verdict
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
