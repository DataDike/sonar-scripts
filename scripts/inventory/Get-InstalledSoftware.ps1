#Requires -Version 5.1
<#
.SYNOPSIS
    Lists installed programs from the machine-wide Uninstall registry keys.

.DESCRIPTION
    Reads HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall and its WOW6432Node copy
    (64-bit and 32-bit programs). Skips system components (SystemComponent = 1), updates
    attached to a parent product (ParentKeyName) and entries without DisplayName, removes
    duplicates and prints name | version | publisher | install date, sorted by name.
    Never queries the MSI provider through CIM (that triggers repairs). Per-user installs (HKCU of each user) are not listed.
    Changes nothing.
    As a check: pass -NameFilter; the script exits 1 when nothing matches, so it answers
    "is X installed".

.PARAMETER NameFilter
    Wildcard applied to the program name (case-insensitive). Default '*' (all programs).

.PARAMETER MaxItems
    Maximum number of programs printed. Default 200. Output is also capped near 4 KB.

.EXAMPLE
    -NameFilter '*Chrome*'

.EXAMPLE
    -MaxItems 50

.NOTES
    Name:       Inventory - Installed software
    GUID:       a356201b-3e9d-4328-b8e6-717d104c6162
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (no program matches -NameFilter, or error)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string]$NameFilter = '*',
    [int]$MaxItems = 200
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output must stay ASCII: strip accents from localized system strings, replace anything else.
function ConvertTo-AsciiText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $d = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $d.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -eq [System.Globalization.UnicodeCategory]::NonSpacingMark) { continue }
        if ([int]$ch -ge 32 -and [int]$ch -le 126) { [void]$sb.Append($ch) } else { [void]$sb.Append('?') }
    }
    return $sb.ToString().Trim()
}

function Get-ShortText([string]$Text, [int]$Max) {
    if ($null -eq $Text) { return '' }
    $t = ConvertTo-AsciiText $Text
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Format-InstallDate([string]$Raw) {
    if ($Raw -match '^\d{8}$') {
        return ('{0}-{1}-{2}' -f $Raw.Substring(0, 4), $Raw.Substring(4, 2), $Raw.Substring(6, 2))
    }
    if ($Raw) { return (Get-ShortText $Raw 12) }
    return '-'
}

$exitCode = 0
try {
    if (-not $NameFilter) { $NameFilter = '*' }
    if ($MaxItems -lt 1) { $MaxItems = 1 }

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $seen = @{}
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop }
            catch { continue }
            $name = [string]$p.DisplayName
            if (-not $name.Trim()) { continue }
            if ([string]$p.SystemComponent -eq '1') { continue }
            if ($p.ParentKeyName) { continue }
            if ($name -notlike $NameFilter) { continue }
            $version = [string]$p.DisplayVersion
            $dedupKey = ($name.Trim() + '|' + $version.Trim()).ToLowerInvariant()
            if ($seen.ContainsKey($dedupKey)) { continue }
            $seen[$dedupKey] = $true
            $items.Add([pscustomobject]@{
                Name      = $name.Trim()
                Version   = $version.Trim()
                Publisher = [string]$p.Publisher
                Date      = [string]$p.InstallDate
            })
        }
    }

    $sorted = @($items | Sort-Object -Property Name, Version)
    $filtered = ($NameFilter -ne '*')

    if ($sorted.Count -eq 0) {
        if ($filtered) {
            Write-Output ("FAIL: no installed program matches '{0}'" -f (Get-ShortText $NameFilter 80))
            $exitCode = 1
        }
        else {
            Write-Output "OK: no program found in the machine-wide Uninstall keys"
        }
    }
    else {
        if ($filtered) {
            Write-Output ("OK: {0} installed program(s) match '{1}'" -f $sorted.Count, (Get-ShortText $NameFilter 80))
        }
        else {
            Write-Output ("OK: {0} installed program(s)" -f $sorted.Count)
        }
        $budget = 3700
        $printed = 0
        foreach ($s in $sorted) {
            if ($printed -ge $MaxItems) { break }
            $line = 'INFO: {0} | {1} | {2} | {3}' -f (Get-ShortText $s.Name 60), (Get-ShortText $s.Version 20), (Get-ShortText $s.Publisher 30), (Format-InstallDate $s.Date)
            $budget -= ($line.Length + 2)
            if ($budget -lt 0) { break }
            Write-Output $line
            $printed++
        }
        if ($printed -lt $sorted.Count) {
            Write-Output ("INFO: {0} more not shown (-MaxItems or 4 KB output limit); narrow with -NameFilter" -f ($sorted.Count - $printed))
        }
    }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
