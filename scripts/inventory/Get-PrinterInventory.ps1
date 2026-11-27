#Requires -Version 5.1
<#
.SYNOPSIS
    Lists the printers installed on the machine and the state of the Print Spooler service.

.DESCRIPTION
    Reads the machine printers with Get-Printer (falls back to Win32_Printer when the
    PrintManagement module is missing): name, driver, port, shared or not, kind (local, network
    TCP/IP or WSD, virtual such as PDF/XPS/fax, or connection to a print server) and status.
    The default printer is a per-user setting and is not reported (the script runs as SYSTEM).
    Printer connections added by a user (\\server\printer) live in that user profile and are not
    listed either. Inventory action, read-only.
    Exit 0 with the list (also when the spooler is stopped, reported as INFO),
    3 when the Print Spooler service does not exist.

.PARAMETER MaxItems
    Maximum number of printers printed (output is also capped at 4 KB). Default 40.

.EXAMPLE
    -MaxItems 20

.NOTES
    Name:       Inventory - Printers
    GUID:       a26a59f9-f393-4c17-8c3b-b4d59a17b212
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); any user can list machine printers
    Exit codes: 0 OK | 1 FAIL (error) | 3 NOT APPLICABLE (no Print Spooler service)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxItems = 40
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
    return ([string]$ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        [string]$ErrorRecord.Exception.Message -match '(?i)access.*denied|0x80070005')
}

# Win32_Printer.PrinterStatus values
$w32Status = @{ 1 = 'Other'; 2 = 'Unknown'; 3 = 'Idle'; 4 = 'Printing'; 5 = 'Warmup'; 6 = 'Stopped printing'; 7 = 'Offline' }

$exitCode = 0
try {
    if ($MaxItems -lt 1) { $MaxItems = 40 }

    $svc = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Output 'INFO: Print Spooler service not present; no printing on this machine'
        $host.SetShouldExit(3); exit 3
    }
    $startType = 'unknown'
    try { $startType = [string](Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -Property StartMode -ErrorAction Stop).StartMode }
    catch { Write-Verbose ('Win32_Service: ' + $_.Exception.Message) }
    $spoolerLine = 'INFO: Print Spooler {0} (start {1})' -f [string]$svc.Status, $startType

    if ([string]$svc.Status -ne 'Running') {
        Write-Output ('INFO: Print Spooler is {0} (start {1}); printers cannot be listed' -f [string]$svc.Status, $startType)
        $host.SetShouldExit(0); exit 0
    }

    # Ports: TCP/IP ports have a host address, WSD ports start with WSD
    $tcpPorts = @{}
    $printers = @()
    $method = 'Get-Printer'
    $useCim = -not (Get-Command -Name Get-Printer -ErrorAction SilentlyContinue)
    if (-not $useCim) {
        try {
            $printers = @(Get-Printer -ErrorAction Stop)
            try {
                foreach ($p in @(Get-PrinterPort -ErrorAction Stop)) {
                    if ($p.PrinterHostAddress -or $p.CimClass.CimClassName -eq 'MSFT_TcpIpPrinterPort') { $tcpPorts[[string]$p.Name] = $true }
                }
            }
            catch { Write-Verbose ('Get-PrinterPort: ' + $_.Exception.Message) }
        }
        catch {
            if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied listing printers (run as SYSTEM or administrator)'; $host.SetShouldExit(1); exit 1 }
            $useCim = $true
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    if ($useCim) {
        $method = 'Win32_Printer'
        foreach ($p in @(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop)) {
            $st = [int]$p.PrinterStatus
            $rows.Add([pscustomobject]@{
                Name = [string]$p.Name; Driver = [string]$p.DriverName; Port = [string]$p.PortName
                Shared = [bool]$p.Shared; ShareName = [string]$p.ShareName; Connection = (-not [bool]$p.Local)
                Status = $(if ($w32Status.ContainsKey($st)) { $w32Status[$st] } else { [string]$st })
            }) | Out-Null
        }
    }
    else {
        foreach ($p in $printers) {
            $rows.Add([pscustomobject]@{
                Name = [string]$p.Name; Driver = [string]$p.DriverName; Port = [string]$p.PortName
                Shared = [bool]$p.Shared; ShareName = [string]$p.ShareName; Connection = ([string]$p.Type -eq 'Connection')
                Status = [string]$p.PrinterStatus
            }) | Out-Null
        }
    }

    $kinds = @{}
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in ($rows | Sort-Object -Property Name)) {
        $port = $r.Port
        if ($r.Connection) { $kind = 'connection' }
        elseif ($port -match '(?i)^(PORTPROMPT:|nul:?|SHRFAX:|FILE:|XPSPort:|Microsoft\.Office\.OneNote|OneNote|PDF)') { $kind = 'virtual' }
        elseif ($tcpPorts.ContainsKey($port) -or $port -match '(?i)^(IP_|WSD|https?://)' -or $port -match '^\d{1,3}(\.\d{1,3}){3}') { $kind = 'network' }
        elseif ($port -match '(?i)^(USB|LPT|COM|DOT4|TS\d)') { $kind = 'local' }
        else { $kind = 'local' }
        $kinds[$kind] = 1 + [int]$kinds[$kind]
        $share = if ($r.Shared) { 'shared as ' + $r.ShareName } else { 'not shared' }
        $status = if ($r.Status) { $r.Status } else { '?' }
        $lines.Add(('INFO: {0} | {1} | {2} | {3} | {4} | {5}' -f (Get-ShortText $r.Name 50), (Get-ShortText $r.Driver 45), (Get-ShortText $port 30), $kind, $share, $status)) | Out-Null
    }

    $summary = ($kinds.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $kinds[$_], $_ }) -join ', '
    if ($rows.Count) { Write-Output ('OK: {0} printer(s) ({1}); Print Spooler running' -f $rows.Count, $summary) }
    else { Write-Output 'OK: no printer installed; Print Spooler running' }

    $budget = 3700 - ($spoolerLine.Length + 2)
    $printed = 0
    foreach ($l in $lines) {
        if ($printed -ge $MaxItems -or ($budget - ($l.Length + 2)) -lt 0) { break }
        $budget -= ($l.Length + 2)
        Write-Output $l
        $printed++
    }
    if ($printed -lt $lines.Count) { Write-Output ('INFO: {0} more not shown' -f ($lines.Count - $printed)) }
    Write-Output (ConvertTo-AsciiText $spoolerLine)
    Write-Output ('INFO: read with ' + $method + '; default printer is per user and not reported')
}
catch {
    if (Test-AccessDenied $_) { Write-Output 'FAIL: access denied listing printers (run as SYSTEM or administrator)' }
    else { Write-Output ('FAIL: could not list printers: ' + (ConvertTo-AsciiText $_.Exception.Message)) }
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
