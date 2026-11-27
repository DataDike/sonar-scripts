#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the programs that start automatically: Run keys, Startup folders and logon tasks.

.DESCRIPTION
    Collects, for the machine and for every user:
      - Run and RunOnce keys of HKLM (64-bit and WOW6432Node) and the policy Run key;
      - Run and RunOnce keys of every user hive loaded in HKEY_USERS (logged-on users);
      - the common Startup folder and the Startup folder of every local profile (shortcuts are
        resolved to their target);
      - scheduled tasks with a logon trigger (tasks under \Microsoft\ are skipped unless
        -IncludeMicrosoftTasks is passed).
    Entries switched off in Task Manager (StartupApproved) are marked "disabled".
    Each line is: location | name | command (command truncated to 120 characters).
    Profiles of users who are not logged on are only covered through their Startup folder.
    Inventory action, read-only; exits 0.

.PARAMETER MaxItems
    Maximum number of entries printed (output is also capped at 4 KB). Default 60.

.PARAMETER IncludeMicrosoftTasks
    Also list logon tasks under \Microsoft\ (many built-in Windows tasks). Default off.

.EXAMPLE
    -MaxItems 40 -IncludeMicrosoftTasks

.NOTES
    Name:       Inventory - Startup programs
    GUID:       8e724f6a-ea0b-45af-854c-eb18e76a4edc
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); without admin rights other users' entries and some tasks are not readable
    Exit codes: 0 OK | 1 FAIL (error)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxItems = 60,
    [switch]$IncludeMicrosoftTasks
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output must stay ASCII: Windows returns localized text (accents are stripped).
function ConvertTo-AsciiText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return ([regex]::Replace($n, '[^\x20-\x7E]', '')).Trim()
}

function Get-ShortText([string]$Text, [int]$Max) {
    $t = ConvertTo-AsciiText $Text
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Test-AccessDenied($ErrorRecord) {
    return ($ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or
        $ErrorRecord.Exception -is [System.Security.SecurityException] -or
        [string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied|0x80070005')
}

function Get-AccountName([string]$Sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

$items = New-Object System.Collections.Generic.List[object]
$script:deniedPlaces = New-Object System.Collections.Generic.List[string]

function Add-StartupItem([string]$Location, [string]$Name, [string]$Command, [bool]$Disabled) {
    $loc = if ($Disabled) { $Location + ' (disabled)' } else { $Location }
    $items.Add([pscustomobject]@{ Location = $loc; Name = $Name; Command = $Command }) | Out-Null
}

# StartupApproved: binary value, first byte odd = switched off in Task Manager
function Get-DisabledSet([string]$Path) {
    $set = @{}
    try {
        if (Test-Path -LiteralPath $Path) {
            $k = Get-Item -LiteralPath $Path -ErrorAction Stop
            foreach ($v in $k.GetValueNames()) {
                $data = $k.GetValue($v)
                if ($data -is [byte[]] -and $data.Length -gt 0 -and ($data[0] -band 1)) { $set[$v.ToLowerInvariant()] = $true }
            }
        }
    }
    catch { Write-Verbose ('StartupApproved: ' + $_.Exception.Message) }
    return $set
}

function Read-RunKey([string]$Path, [string]$Label, [hashtable]$Disabled) {
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($v in $k.GetValueNames()) {
            if (-not $v) { continue }
            $cmd = [string]$k.GetValue($v, $null, 'DoNotExpandEnvironmentNames')
            $off = $false
            if ($Disabled) { $off = $Disabled.ContainsKey($v.ToLowerInvariant()) }
            Add-StartupItem $Label $v $cmd $off
        }
    }
    catch {
        if (Test-AccessDenied $_) { $script:deniedPlaces.Add($Label) | Out-Null }
        else { Write-Verbose ($Label + ': ' + $_.Exception.Message) }
    }
}

$script:shell = $null
function Read-StartupFolder([string]$Folder, [string]$Label, [hashtable]$Disabled) {
    try {
        if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return }
        foreach ($f in @(Get-ChildItem -LiteralPath $Folder -Force -File -ErrorAction Stop)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $cmd = $f.FullName
            if ($f.Extension -ieq '.lnk') {
                try {
                    if (-not $script:shell) { $script:shell = New-Object -ComObject WScript.Shell }
                    $lnk = $script:shell.CreateShortcut($f.FullName)
                    if ($lnk.TargetPath) { $cmd = ([string]$lnk.TargetPath + ' ' + [string]$lnk.Arguments).Trim() }
                }
                catch { Write-Verbose ('shortcut: ' + $_.Exception.Message) }
            }
            $off = $false
            if ($Disabled) { $off = $Disabled.ContainsKey($f.Name.ToLowerInvariant()) }
            Add-StartupItem $Label $f.Name $cmd $off
        }
    }
    catch {
        if (Test-AccessDenied $_) { $script:deniedPlaces.Add($Label) | Out-Null }
        else { Write-Verbose ($Label + ': ' + $_.Exception.Message) }
    }
}

$exitCode = 0
try {
    if ($MaxItems -lt 1) { $MaxItems = 60 }
    $cv = 'SOFTWARE\Microsoft\Windows\CurrentVersion'
    $approved = 'HKLM:\' + $cv + '\Explorer\StartupApproved'

    # --- machine Run keys ---
    $offRun = Get-DisabledSet ($approved + '\Run')
    $offRun32 = Get-DisabledSet ($approved + '\Run32')
    Read-RunKey ('HKLM:\' + $cv + '\Run') 'HKLM Run' $offRun
    Read-RunKey ('HKLM:\' + $cv + '\RunOnce') 'HKLM RunOnce' $null
    Read-RunKey ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') 'HKLM Run (32-bit)' $offRun32
    Read-RunKey ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') 'HKLM RunOnce (32-bit)' $null
    Read-RunKey ('HKLM:\' + $cv + '\Policies\Explorer\Run') 'HKLM Policy Run' $null

    # --- loaded user hives ---
    $userHives = @()
    try {
        # GetSubKeyNames does not open the subkeys (Get-ChildItem stops on the first denied hive)
        $userHives = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() |
            Where-Object { $_ -match '^S-1-(5-21|12-1)-[\d-]+$' })
    }
    catch { Write-Verbose ('HKEY_USERS: ' + $_.Exception.Message) }
    foreach ($h in $userHives) {
        $sid = [string]$h
        $who = Get-AccountName $sid
        $base = 'Registry::HKEY_USERS\' + $sid + '\' + $cv
        $offUser = Get-DisabledSet ($base + '\Explorer\StartupApproved\Run')
        Read-RunKey ($base + '\Run') ('HKU ' + $who + ' Run') $offUser
        Read-RunKey ($base + '\RunOnce') ('HKU ' + $who + ' RunOnce') $null
        Read-RunKey ($base + '\Policies\Explorer\Run') ('HKU ' + $who + ' Policy Run') $null
    }

    # --- Startup folders ---
    $offFolder = Get-DisabledSet ($approved + '\StartupFolder')
    Read-StartupFolder ([Environment]::GetFolderPath('CommonStartup')) 'Startup (all users)' $offFolder
    $loadedSids = @{}
    foreach ($h in $userHives) { $loadedSids[[string]$h] = $true }
    $profiles = @()
    try { $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = False' -Property SID, LocalPath -ErrorAction Stop) }
    catch { Write-Verbose ('Win32_UserProfile: ' + $_.Exception.Message) }
    foreach ($p in $profiles) {
        if (-not $p.LocalPath) { continue }
        $folder = Join-Path ([string]$p.LocalPath) 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        $offU = $null
        if ($loadedSids.ContainsKey([string]$p.SID)) {
            $offU = Get-DisabledSet ('Registry::HKEY_USERS\' + $p.SID + '\' + $cv + '\Explorer\StartupApproved\StartupFolder')
        }
        Read-StartupFolder $folder ('Startup ' + (Get-AccountName ([string]$p.SID))) $offU
    }

    # --- logon-triggered scheduled tasks ---
    $taskNote = $null
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        $skipped = 0
        foreach ($t in $tasks) {
            $logon = @($t.Triggers | Where-Object { $_ -and $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' })
            if (-not $logon.Count) { continue }
            if (-not $IncludeMicrosoftTasks -and ([string]$t.TaskPath) -like '\Microsoft\*') { $skipped++; continue }
            $cmds = foreach ($a in @($t.Actions)) {
                if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction') { ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim() }
                elseif ($a) { 'COM handler ' + [string]$a.ClassId }
            }
            Add-StartupItem ('Task ' + [string]$t.TaskPath) ([string]$t.TaskName) (@($cmds) -join ' ; ') ([string]$t.State -eq 'Disabled')
        }
        if ($skipped) { $taskNote = ('INFO: {0} built-in logon task(s) under \Microsoft\ skipped (-IncludeMicrosoftTasks to list)' -f $skipped) }
    }
    catch {
        if (Test-AccessDenied $_) { $script:deniedPlaces.Add('scheduled tasks') | Out-Null }
        else { $taskNote = 'INFO: scheduled tasks not read: ' + (ConvertTo-AsciiText $_.Exception.Message) }
    }

    $regCount = @($items | Where-Object { $_.Location -like 'HK*' }).Count
    $folderCount = @($items | Where-Object { $_.Location -like 'Startup*' }).Count
    $taskCount = @($items | Where-Object { $_.Location -like 'Task *' }).Count
    Write-Output ('OK: {0} startup item(s): {1} registry, {2} Startup folder, {3} logon task(s); {4} user hive(s) loaded' -f $items.Count, $regCount, $folderCount, $taskCount, $userHives.Count)

    $footer = New-Object System.Collections.Generic.List[string]
    if ($taskNote) { $footer.Add($taskNote) | Out-Null }
    if ($script:deniedPlaces.Count) {
        $footer.Add((Get-ShortText ('INFO: access denied (run as SYSTEM or administrator): ' + (($script:deniedPlaces | Select-Object -Unique) -join ', ')) 400)) | Out-Null
    }
    $budget = 3850 - 50
    foreach ($f in $footer) { $budget -= ($f.Length + 2) }
    $printed = 0
    foreach ($i in $items) {
        $line = 'INFO: {0} | {1} | {2}' -f (Get-ShortText $i.Location 50), (Get-ShortText $i.Name 50), (Get-ShortText $i.Command 120)
        if ($printed -ge $MaxItems -or ($budget - ($line.Length + 2)) -lt 0) { break }
        $budget -= ($line.Length + 2)
        Write-Output $line
        $printed++
    }
    if ($printed -lt $items.Count) { Write-Output ('INFO: {0} more not shown (-MaxItems or 4 KB output limit)' -f ($items.Count - $printed)) }
    foreach ($f in $footer) { Write-Output $f }
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied reading startup locations (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not list startup programs: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
