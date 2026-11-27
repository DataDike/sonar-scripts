#Requires -Version 5.1
<#
.SYNOPSIS
    Lists Chrome, Edge and Firefox extensions of every user profile; fails on blocked extension ids.

.DESCRIPTION
    Walks the user profiles registered on the machine (ProfileList, local and domain/Entra users)
    and reads, without starting any browser:
      - Chrome and Edge: every browser profile (Default, Profile N) folder Extensions\<id>\<version>,
        name from manifest.json (localized __MSG_ names resolved through _locales\<default_locale>
        or _locales\en messages.json);
      - Firefox: extensions.json of every profile (user-installed add-ons of type extension).
    Prints browser | user | name | id | version. It does not tell whether a Chrome/Edge extension
    is disabled (that state lives in the encrypted Secure Preferences and is not read). Read-only.
    As SYSTEM every profile is readable; a standard user only reads its own.

.PARAMETER BlockList
    Extension ids that must not be installed (Chrome/Edge 32-letter ids or Firefox add-on ids,
    wildcards allowed), as a list or one comma-separated string. Default: none (inventory only).

.EXAMPLE
    -BlockList "aaaabbbbccccddddeeeeffffgggghhhh,{00000000-0000-0000-0000-000000000000}"

.NOTES
    Name:       Security - Browser extensions
    GUID:       4110f4a0-4b30-4cb7-b733-700da05c6a2a
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator to read every user profile)
    Exit codes: 0 OK | 1 FAIL (blocked extension found, or error)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string[]]$BlockList = @()
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

function Read-Json([string]$Path) {
    $raw = [System.IO.File]::ReadAllText($Path)
    return ($raw | ConvertFrom-Json)
}

# Case-insensitive lookup of a message key in a _locales messages.json
function Get-LocaleMessage([string]$ExtDir, [string]$DefaultLocale, [string]$Key) {
    $locales = @()
    if ($DefaultLocale) { $locales += $DefaultLocale }
    $locales += 'en', 'en_US', 'en_GB'
    foreach ($loc in ($locales | Select-Object -Unique)) {
        $file = Join-Path $ExtDir ('_locales\' + $loc + '\messages.json')
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $msgs = Read-Json $file
            foreach ($p in $msgs.PSObject.Properties) {
                if ($p.Name -eq $Key -and $p.Value.message) { return [string]$p.Value.message }
            }
        }
        catch { Write-Verbose ('messages.json not readable: ' + $file) }
    }
    return $null
}

$exitCode = 0
try {
    $blocked = @($BlockList | ForEach-Object { [string]$_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    # User profiles: S-1-5-21 (local/domain) and S-1-12-1 (Entra)
    $homes = New-Object System.Collections.Generic.List[object]
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop)) {
        if ($k.PSChildName -notmatch '^S-1-(5-21|12-1)-') { continue }
        $p = [string]$k.GetValue('ProfileImagePath')
        if ($p) { $homes.Add([pscustomobject]@{ User = (Split-Path -Leaf $p); Path = [Environment]::ExpandEnvironmentVariables($p) }) | Out-Null }
    }

    $found = New-Object System.Collections.Generic.List[object]
    $unreadable = New-Object System.Collections.Generic.List[string]
    $chromium = @(
        @{ Name = 'Chrome'; Rel = 'AppData\Local\Google\Chrome\User Data' },
        @{ Name = 'Edge'; Rel = 'AppData\Local\Microsoft\Edge\User Data' }
    )

    foreach ($h in $homes) {
        if (-not (Test-Path -LiteralPath $h.Path)) { continue }
        try { $null = Get-ChildItem -LiteralPath $h.Path -Force -ErrorAction Stop | Select-Object -First 1 }
        catch { $unreadable.Add($h.User) | Out-Null; continue }

        foreach ($b in $chromium) {
            $userData = Join-Path $h.Path $b.Rel
            if (-not (Test-Path -LiteralPath $userData)) { continue }
            $profiles = @(Get-ChildItem -LiteralPath $userData -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
            foreach ($prof in $profiles) {
                $extRoot = Join-Path $prof.FullName 'Extensions'
                if (-not (Test-Path -LiteralPath $extRoot)) { continue }
                foreach ($idDir in @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {
                    if ($idDir.Name -notmatch '^[a-p]{32}$') { continue }
                    $verDir = Get-ChildItem -LiteralPath $idDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                    if (-not $verDir) { continue }
                    $name = $idDir.Name; $version = ($verDir.Name -replace '_\d+$', '')
                    $manifest = Join-Path $verDir.FullName 'manifest.json'
                    if (Test-Path -LiteralPath $manifest) {
                        try {
                            $m = Read-Json $manifest
                            if ($m.version) { $version = [string]$m.version }
                            $n = [string]$m.name
                            if ($n -match '^__MSG_(.+)__$') {
                                $resolved = Get-LocaleMessage $verDir.FullName ([string]$m.default_locale) $Matches[1]
                                if ($resolved) { $n = $resolved }
                            }
                            if ($n) { $name = $n }
                        }
                        catch { Write-Verbose ('manifest not readable: ' + $manifest) }
                    }
                    $browserName = if ($prof.Name -eq 'Default') { $b.Name } else { $b.Name + ' (' + $prof.Name + ')' }
                    $found.Add([pscustomobject]@{ Browser = $browserName; User = $h.User; Name = $name; Id = $idDir.Name; Version = $version }) | Out-Null
                }
            }
        }

        # Firefox
        $ffRoot = Join-Path $h.Path 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ffRoot) {
            foreach ($ffProf in @(Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
                $json = Join-Path $ffProf.FullName 'extensions.json'
                if (-not (Test-Path -LiteralPath $json)) { continue }
                try {
                    $data = Read-Json $json
                    foreach ($ad in @($data.addons)) {
                        if ([string]$ad.type -ne 'extension') { continue }
                        if ([string]$ad.location -match '^app-(builtin|system)') { continue }
                        $nm = if ($ad.defaultLocale -and $ad.defaultLocale.name) { [string]$ad.defaultLocale.name } else { [string]$ad.id }
                        if (-not $ad.active) { $nm = $nm + ' (inactive)' }
                        $found.Add([pscustomobject]@{ Browser = 'Firefox'; User = $h.User; Name = $nm; Id = [string]$ad.id; Version = [string]$ad.version }) | Out-Null
                    }
                }
                catch { Write-Verbose ('extensions.json not readable: ' + $json) }
            }
        }
    }

    $hits = @($found | Where-Object { $ext = $_; @($blocked | Where-Object { $ext.Id -like $_ }).Count -gt 0 })
    $users = @($found | ForEach-Object { $_.User } | Select-Object -Unique).Count
    if ($hits.Count) {
        Write-Line ('FAIL: {0} blocked extension(s) installed: {1}' -f $hits.Count, ((@($hits | ForEach-Object { (Limit-Text $_.Name 30) + ' (' + $_.User + ')' }) | Select-Object -First 10) -join ', '))
        $exitCode = 1
    }
    else {
        Write-Line ('OK: {0} browser extension(s) found in {1} user profile(s){2}' -f $found.Count, $users, $(if ($blocked.Count) { ', none blocked' } else { '' }))
    }

    # Blocked first, then the rest; keep the output small
    $ordered = @($hits) + @($found | Where-Object { $hits -notcontains $_ } | Sort-Object -Property User, Browser, Name)
    $n = 0; $bytes = 0
    foreach ($e in $ordered) {
        $prefix = if ($hits -contains $e) { 'FAIL' } else { 'INFO' }
        $line = '{0}: {1} | {2} | {3} | {4} | {5}' -f $prefix, $e.Browser, $e.User, (Limit-Text $e.Name 40), (Limit-Text $e.Id 40), (Limit-Text $e.Version 20)
        if ($n -ge 30 -or ($bytes + $line.Length) -gt 3000) { Write-Line ('INFO: {0} more extension(s) not shown' -f ($ordered.Count - $n)); break }
        Write-Line $line
        $bytes += $line.Length + 2
        $n++
    }
    if ($unreadable.Count) { Write-Line ('INFO: {0} user profile(s) not readable by this account (run as SYSTEM)' -f $unreadable.Count) }
}
catch {
    Write-Line ('FAIL: could not list browser extensions: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
