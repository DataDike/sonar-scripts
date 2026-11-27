#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that one or more Windows services are running, optionally starting them.

.DESCRIPTION
    Reads the state of each service given in -Name (service name, not display name).
    With -Restart, a stopped service is started (Start-Service) and the result reported;
    the script never stops, disables or reconfigures a service.
    Use it as a check: 0 when all services run, 1 when any service is not running
    (after the optional start), 3 when a service does not exist on the machine
    (and none of the existing ones is failing).

.PARAMETER Name
    Required. Service name, or several separated by commas (for example 'Winmgmt,EventLog').
    Wildcards are not accepted.

.PARAMETER Restart
    Try to start each service that is not running, then report its new state. Default off.

.EXAMPLE
    -Name Winmgmt

.EXAMPLE
    -Name 'Spooler,EventLog' -Restart

.NOTES
    Name:       Services - Service running
    GUID:       ba2725b8-7a9b-42fc-bd9f-77cd616f6037
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (not running, or error) | 3 NOT APPLICABLE (service does not exist)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string]$Name = '',
    [switch]$Restart
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

$exitCode = 0
try {
    $names = @($Name -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($names.Count -eq 0) {
        Write-Output "FAIL: -Name is required (service name, comma-separated for several)"
        $host.SetShouldExit(1); exit 1
    }
    if (@($names | Where-Object { $_ -match '[\*\?\[\]]' }).Count -gt 0) {
        Write-Output "FAIL: wildcards are not accepted in -Name"
        $host.SetShouldExit(1); exit 1
    }

    $running = 0; $failed = 0; $missing = 0
    $details = New-Object System.Collections.Generic.List[string]
    foreach ($n in $names) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            $missing++
            $details.Add(("INFO: {0}: service does not exist" -f $n))
            continue
        }
        if ($svc.Status -ne 'Running' -and $Restart) {
            try {
                Start-Service -InputObject $svc -ErrorAction Stop
                $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                $details.Add(("INFO: {0}: was {1}, start requested" -f $svc.Name, 'not running'))
            }
            catch {
                $details.Add(("INFO: {0}: start failed: {1}" -f $svc.Name, $_.Exception.Message))
            }
            $svc.Refresh()
        }
        if ($svc.Status -eq 'Running') {
            $running++
            $details.Add(("OK: {0} ({1}) is running, start type {2}" -f $svc.Name, (ConvertTo-AsciiText $svc.DisplayName), $svc.StartType))
        }
        else {
            $failed++
            $details.Add(("FAIL: {0} ({1}) is {2}, start type {3}" -f $svc.Name, (ConvertTo-AsciiText $svc.DisplayName), $svc.Status, $svc.StartType))
        }
    }

    if ($failed -gt 0) {
        Write-Output ("FAIL: {0} of {1} service(s) not running" -f $failed, $names.Count)
        $exitCode = 1
    }
    elseif ($missing -gt 0) {
        Write-Output ("INFO: {0} of {1} service(s) do not exist on this machine; {2} running" -f $missing, $names.Count, $running)
        $exitCode = 3
    }
    else {
        Write-Output ("OK: {0} service(s) running" -f $running)
    }
    $details | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
