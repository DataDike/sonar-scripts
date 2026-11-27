#Requires -Version 5.1
<#
.SYNOPSIS
    Validates the manifest and every script of the SONAR script library.

.DESCRIPTION
    Run with Windows PowerShell 5.1 from the repository root:
        powershell -NoProfile -File tools/validate.ps1
    Checks: manifest schema, unique GUIDs and names, files present (both ways), header GUID and
    version, PowerShell 5.1 parse, ASCII only, size, forbidden patterns and, when the module is
    installed, PSScriptAnalyzer. Exits 1 when anything fails.
#>
[CmdletBinding()]
param(
    [string]$Root,
    # Validate a partial manifest (work in progress); skips the 'file not in manifest' check.
    [string]$Manifest,
    [switch]$SkipAnalyzer
)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$Root = (Resolve-Path $Root).Path
$errors = New-Object System.Collections.Generic.List[string]
function Add-Err([string]$msg) { $errors.Add($msg) | Out-Null }

$manifestPath = if ($Manifest) { $Manifest } else { Join-Path $Root 'sonar_scripts.json' }
$scriptsRoot = Join-Path $Root 'scripts'

$required = 'guid', 'filename', 'name', 'description', 'shell', 'category', 'args', 'env',
            'syntax', 'default_timeout', 'supported_platforms', 'run_as_user'
$shells = 'powershell', 'cmd', 'python', 'shell', 'nushell', 'deno'
$platforms = 'windows', 'linux', 'darwin'
$extByShell = @{ powershell = '.ps1'; cmd = '.bat'; python = '.py'; shell = '.sh'; nushell = '.nu'; deno = '.ts' }

# Patterns that must never appear in a library script. Each is a regex (case-insensitive).
$forbidden = [ordered]@{
    'Invoke-Expression / iex'          = '(?<![\w-])(Invoke-Expression|iex)(?![\w-])'
    'remote code download'             = 'DownloadString|DownloadFile|Net\.WebClient'
    'runtime module install'           = 'Install-Module|Install-Package|Install-PackageProvider'
    'Win32_Product (MSI repair)'       = 'Win32_Product'
    'Get-WmiObject (use CIM)'          = 'Get-WmiObject|gwmi\s'
    'hard-coded credential'            = '(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*=\s*["''][^"''$]{4,}["'']'
    'private key material'             = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'e-mail address'                   = '[A-Za-z0-9._%+-]+@(?!example\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    'private IP address'               = '\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b'
    'upstream product name'            = '(?i)tactical|trmm|amidaware'
    'unconditional reboot'             = '(?i)Restart-Computer(?![^\r\n]*AllowReboot)'
}

if (-not (Test-Path $manifestPath)) { Write-Output "FAIL: sonar_scripts.json not found"; exit 1 }
try {
    $entries = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json
} catch {
    Write-Output ("FAIL: sonar_scripts.json is not valid JSON: " + $_.Exception.Message); exit 1
}
$entries = @($entries | ForEach-Object { $_ } | Where-Object { $_ -ne $null -and @($_.PSObject.Properties).Count -gt 0 })

$guids = @{}; $names = @{}; $files = @{}
foreach ($e in $entries) {
    $id = if ($e.name) { $e.name } else { '<no name>' }
    foreach ($f in $required) {
        if (-not ($e.PSObject.Properties.Name -contains $f)) { Add-Err "$id : missing field '$f'" }
    }
    if ($e.guid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { Add-Err "$id : guid must be a lowercase UUID" }
    if ($guids.ContainsKey([string]$e.guid)) { Add-Err "$id : duplicated guid $($e.guid)" } else { $guids[[string]$e.guid] = $true }
    if ($names.ContainsKey([string]$e.name)) { Add-Err "$id : duplicated name" } else { $names[[string]$e.name] = $true }
    if ($shells -notcontains $e.shell) { Add-Err "$id : invalid shell '$($e.shell)'" }
    foreach ($p in @($e.supported_platforms)) { if ($platforms -notcontains $p) { Add-Err "$id : invalid platform '$p'" } }
    if (-not ($e.default_timeout -is [int] -or $e.default_timeout -is [long]) -or $e.default_timeout -lt 10 -or $e.default_timeout -gt 3600) { Add-Err "$id : default_timeout must be an integer 10-3600" }
    if ($e.name -notmatch '^[A-Za-z][A-Za-z ]* - .+') { Add-Err "$id : name must be 'Category - Short name'" }
    if (-not ([string]$e.name).StartsWith([string]$e.category + ' - ')) { Add-Err "$id : name must start with the category" }
    if ([string]$e.filename -notmatch '^[a-z0-9-]+/[A-Za-z0-9-]+\.[a-z0-9]+$') { Add-Err "$id : filename must be '<category-folder>/<Verb-Noun>.<ext>'" }
    if ($extByShell.ContainsKey([string]$e.shell) -and -not ([string]$e.filename).EndsWith($extByShell[[string]$e.shell])) { Add-Err "$id : extension does not match shell" }
    foreach ($a in @($e.args) + @($e.env)) {
        if ($a -match '(?i)(password|secret|token|key)\s*[= ]\s*\S{4,}' -and $a -notmatch '\{\{') { Add-Err "$id : looks like a secret in args/env defaults" }
    }
    foreach ($s in @($e.name, $e.description, $e.syntax) + @($e.args) + @($e.env)) {
        if ($s -and ([string]$s -match '[^\x09\x0A\x0D\x20-\x7E]')) { Add-Err "$id : non-ASCII text in manifest" }
    }

    $path = Join-Path $scriptsRoot ([string]$e.filename)
    $files[(Resolve-Path -LiteralPath $path -ErrorAction SilentlyContinue).Path] = $true
    if (-not (Test-Path -LiteralPath $path)) { Add-Err "$id : file not found scripts/$($e.filename)"; continue }

    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -gt 64KB) { Add-Err "$id : file larger than 64 KB" }
    foreach ($b in $bytes) { if ($b -gt 127) { Add-Err "$id : non-ASCII byte in script (keep scripts ASCII only)"; break } }
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)

    foreach ($k in $forbidden.Keys) {
        if ($text -match $forbidden[$k]) { Add-Err "$id : forbidden pattern ($k): '$($Matches[0])'" }
    }

    if ($e.shell -eq 'powershell') {
        $tokens = $null; $perr = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$perr) | Out-Null
        foreach ($pe in @($perr)) { if ($pe) { Add-Err "$id : parse error line $($pe.Extent.StartLineNumber): $($pe.Message)" } }
        if ($text -notmatch '(?m)^#Requires -Version 5\.1') { Add-Err "$id : missing '#Requires -Version 5.1'" }
        foreach ($tag in '.SYNOPSIS', '.DESCRIPTION', '.NOTES', '.LINK') { if ($text -notmatch [regex]::Escape($tag)) { Add-Err "$id : header missing $tag" } }
        if ($text -notmatch ('GUID:\s+' + [regex]::Escape([string]$e.guid))) { Add-Err "$id : header GUID differs from manifest" }
        if ($text -notmatch 'Version:\s+\d+\.\d+\.\d+') { Add-Err "$id : header missing semver Version" }
        if ($text -notmatch '(?m)(^|[;{]\s*)exit\s') { Add-Err "$id : script must end with an explicit exit code" }
        # the agent runs scripts without -File: a plain 'exit 2' reaches the console as 1
        foreach ($ln in ($text -split "`r?`n")) {
            if ($ln -match '(^|[;{]\s*)exit\s+\S' -and $ln -notmatch '^\s*#' -and $ln -notmatch 'SetShouldExit') {
                Add-Err "$id : use '`$host.SetShouldExit(N); exit N' (plain exit loses codes 2/3): $($ln.Trim())"; break
            }
        }
        if ($text -match '(?i)Remove-Item|Clear-RecycleBin|Reset-|netsh\s+winsock\s+reset|Stop-Service|Set-Service') {
            if ($text -notmatch '\[switch\]\$DryRun') { Add-Err "$id : changes the system but has no -DryRun switch" }
        }
        # PowerShell 7-only syntax that the 5.1 parser may not flag in every position
        if ($text -match '\?\?=?|\s-Parallel\b') { Add-Err "$id : PowerShell 7-only syntax" }
    }
}

# every file under scripts/ must be in the manifest
if (-not $Manifest -and (Test-Path $scriptsRoot)) {
    Get-ChildItem -Path $scriptsRoot -Recurse -File | ForEach-Object {
        if (-not $files.ContainsKey($_.FullName)) { Add-Err ("file not in manifest: " + $_.FullName.Substring($Root.Length + 1)) }
    }
}

if (-not $SkipAnalyzer) {
    if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
        Import-Module PSScriptAnalyzer
        $findings = $entries | ForEach-Object { Invoke-ScriptAnalyzer -Path (Join-Path $scriptsRoot $_.filename) -Severity Error, Warning `
            -ExcludeRule PSAvoidUsingWriteHost, PSUseShouldProcessForStateChangingFunctions, PSAvoidUsingPositionalParameters, PSAvoidDefaultValueSwitchParameter }
        foreach ($f in $findings) { Add-Err ("analyzer {0}:{1} {2} {3}" -f (Split-Path -Leaf $f.ScriptPath), $f.Line, $f.RuleName, $f.Message) }
    } else {
        Write-Output "INFO: PSScriptAnalyzer not installed; analyzer step skipped (CI runs it)"
    }
}

if ($errors.Count) {
    Write-Output ("FAIL: {0} problem(s) in {1} script(s)" -f $errors.Count, $entries.Count)
    $errors | ForEach-Object { Write-Output ("  - " + $_) }
    exit 1
}
Write-Output ("OK: {0} script(s) valid" -f $entries.Count)
exit 0
