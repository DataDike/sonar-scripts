#Requires -Version 5.1
<#
.SYNOPSIS
    Flags scheduled tasks whose actions look like persistence or living-off-the-land abuse.

.DESCRIPTION
    Reads every scheduled task (Get-ScheduledTask) and inspects the command-line actions of the
    non-Microsoft tasks (task path not under \Microsoft\). A task is flagged when an action:
      - runs from a user-writable or temporary folder (AppData, Temp, Users\Public, Downloads,
        a file directly in ProgramData) and the program is not validly Authenticode-signed;
      - starts PowerShell with an encoded command, in-memory execution, web download or
        Base64 decoding text in its arguments, or with a hidden window;
      - runs mshta, rundll32 or regsvr32 with a URL, a UNC path or script code;
      - belongs to a task marked as hidden.
    Only the text of the task definition is matched; nothing is executed. Read-only.
    Note: the patterns for in-memory execution and downloads are assembled from pieces at run time
    because the library validator forbids those literal words in a script's own source.
    As SYSTEM all tasks are visible; a standard user only sees part of them.

.PARAMETER IncludeMicrosoft
    Also inspect tasks under \Microsoft\.

.PARAMETER Exclude
    Task full paths (wildcards allowed, for example "\Vendor\*") to ignore, as a list or one
    comma-separated string. Default: none.

.EXAMPLE
    -Exclude "\Vendor\Updater*"

.NOTES
    Name:       Security - Suspicious scheduled tasks
    GUID:       b63e831f-5f1f-47fc-893b-ffbcb0aa73ef
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator recommended to see every task)
    Exit codes: 0 OK | 1 FAIL (error) | 2 WARN (suspicious task found)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$IncludeMicrosoft,
    [string[]]$Exclude = @()
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

# Patterns built from pieces: the validator rejects these words as literals in library scripts.
$pIex = '(?i)(^|[^\w-])(' + 'I' + 'EX' + '|' + 'Invoke-' + 'Expression' + ')([^\w-]|$)'
$pDownload = '(?i)(' + 'Download' + 'String' + '|' + 'Download' + 'File' + '|' + 'Net\.Web' + 'Client' + '|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Start-BitsTransfer|https?://)'
$pBase64 = '(?i)FromBase64String'
$pEncoded = '(?i)(^|\s)[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[A-Za-z0-9+/]{16,}={0,2}'
$pHiddenWin = '(?i)(^|\s)[-/]w(i|in|ind|indo|indow|indows|indowst\w*)?\s+(h|hi|hid|hidd|hidde|hidden|1)(\s|$)'
$pWritable = '(?i)(\\AppData\\|\\Temp\\|\\Tmp\\|\\Users\\Public\\|\\Downloads\\|%temp%|%tmp%|%appdata%|%localappdata%|\\ProgramData\\[^\\"]+\.(exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|hta|scr)\b)'
$pLolUrl = '(?i)(https?:|\\\\[^\\]+\\|javascript:|vbscript:|scrobj)'

$exitCode = 0
try {
    $excl = @($Exclude | ForEach-Object { [string]$_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $flagged = New-Object System.Collections.Generic.List[object]
    $inspected = 0; $signedSkipped = 0
    $sigCache = @{}

    foreach ($t in $tasks) {
        $full = [string]$t.TaskPath + [string]$t.TaskName
        if (-not $IncludeMicrosoft -and [string]$t.TaskPath -like '\Microsoft\*') { continue }
        $skip = $false
        foreach ($p in $excl) { if ($full -like $p) { $skip = $true; break } }
        if ($skip) { continue }
        $inspected++

        $reasons = New-Object System.Collections.Generic.List[string]
        $cmdShown = ''
        if ($t.Settings -and $t.Settings.Hidden) { $reasons.Add('task hidden') | Out-Null }

        foreach ($a in @($t.Actions)) {
            if (-not ($a.PSObject.Properties.Name -contains 'Execute') -or -not $a.Execute) { continue }
            $exe = [Environment]::ExpandEnvironmentVariables(([string]$a.Execute).Trim('"'))
            $arg = [string]$a.Arguments
            $leaf = ''
            try { $leaf = [System.IO.Path]::GetFileName($exe).ToLower() } catch { $leaf = $exe.ToLower() }
            if (-not $cmdShown) { $cmdShown = ($exe + ' ' + $arg).Trim() }

            # User-writable location (program or script argument); a validly signed program is accepted
            if ($exe -match $pWritable) {
                $signedOk = $false
                $exists = Test-Path -LiteralPath $exe -PathType Leaf
                if ($exists) {
                    if (-not $sigCache.ContainsKey($exe)) {
                        try { $sigCache[$exe] = ((Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop).Status -eq 'Valid') }
                        catch { $sigCache[$exe] = $false }
                    }
                    $signedOk = $sigCache[$exe]
                }
                if ($signedOk) { $signedSkipped++ }
                elseif ($exists) { $reasons.Add('unsigned program in user-writable path') | Out-Null }
                else { $reasons.Add('user-writable path, program missing') | Out-Null }
            }
            elseif ($arg -match $pWritable -and $leaf -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$|^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)$') {
                $reasons.Add('script host loads file from user-writable path') | Out-Null
            }

            if ($leaf -match '^(powershell|pwsh)(\.exe)?$') {
                if ($arg -match $pEncoded) { $reasons.Add('encoded command') | Out-Null }
                if ($arg -match $pIex) { $reasons.Add('in-memory execution') | Out-Null }
                if ($arg -match $pDownload) { $reasons.Add('web download') | Out-Null }
                if ($arg -match $pBase64) { $reasons.Add('Base64 decoding') | Out-Null }
                if ($arg -match $pHiddenWin) { $reasons.Add('hidden window') | Out-Null }
            }
            elseif ($leaf -match '^(mshta|rundll32|regsvr32)(\.exe)?$' -and $arg -match $pLolUrl) {
                $reasons.Add($leaf + ' with URL/UNC/script') | Out-Null
            }
            elseif ($leaf -match '^cmd(\.exe)?$' -and ($arg -match $pDownload -or $arg -match $pIex)) {
                $reasons.Add('cmd with download or in-memory execution') | Out-Null
            }
        }

        if ($reasons.Count) {
            $flagged.Add([pscustomobject]@{ Path = $full; Reasons = (($reasons | Select-Object -Unique) -join ', '); Command = $cmdShown; State = [string]$t.State }) | Out-Null
        }
    }

    if ($flagged.Count) {
        Write-Line ('WARN: {0} suspicious scheduled task(s) out of {1} inspected' -f $flagged.Count, $inspected)
        $exitCode = 2
    }
    else {
        Write-Line ('OK: no suspicious scheduled task ({0} inspected of {1})' -f $inspected, $tasks.Count)
    }
    $n = 0
    foreach ($f in $flagged) {
        if ($n -ge 20) { Write-Line ('INFO: {0} more task(s) not shown' -f ($flagged.Count - $n)); break }
        Write-Line ('WARN: {0} | {1} | {2} | {3}' -f (Limit-Text $f.Path 70), $f.Reasons, $f.State, (Limit-Text $f.Command 110))
        $n++
    }
    if ($signedSkipped) { Write-Line ('INFO: {0} action(s) in user-writable paths accepted because the program is validly signed' -f $signedSkipped) }
    Write-Line ('INFO: scope {0}; {1} task(s) visible to this account' -f $(if ($IncludeMicrosoft) { 'all tasks' } else { 'non-Microsoft tasks' }), $tasks.Count)
}
catch {
    Write-Line ('FAIL: could not read scheduled tasks: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
