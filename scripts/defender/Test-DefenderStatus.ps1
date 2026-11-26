#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that Microsoft Defender Antivirus is running, protecting and up to date.

.DESCRIPTION
    Read-only check based on Get-MpComputerStatus: antimalware service, antivirus, real-time
    protection, tamper protection, running mode (Normal, Passive, EDR Block) and signature age.

    Verdict rules:
      FAIL (1) service or antivirus disabled, real-time protection off (Normal mode), Defender not
               running, or Passive / EDR Block mode without -AllowPassive.
      WARN (2) signatures older than -MaxSignatureAgeDays, or tamper protection off.
      N/A  (3) Defender is not available (cmdlets or WinDefend service missing, or Defender turned
               off because a third-party antivirus is registered and Defender is not even passive).
      OK   (0) otherwise. With -AllowPassive, Passive and EDR Block modes are accepted and the
               real-time protection rule is skipped (another antivirus protects the machine).

.PARAMETER MaxSignatureAgeDays
    Maximum age of the antivirus signatures, in days, before a warning. Default 3.

.PARAMETER AllowPassive
    Accept Passive / EDR Block mode (another antivirus is the primary one).

.EXAMPLE
    -MaxSignatureAgeDays 2 -AllowPassive

.NOTES
    Name:       Defender - Protection status
    GUID:       e04da0af-997b-4b04-8c38-f806f320a16b
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator); also works as a standard user
    Exit codes: 0 OK | 1 FAIL | 2 WARN | 3 NOT APPLICABLE
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MaxSignatureAgeDays = 3,
    [switch]$AllowPassive
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$lines = New-Object System.Collections.Generic.List[string]
$script:isFail = $false
$script:isWarn = $false
function Add-Fail([string]$msg) { $script:isFail = $true; $lines.Add('FAIL: ' + $msg) }
function Add-Warn([string]$msg) { $script:isWarn = $true; $lines.Add('WARN: ' + $msg) }
function Add-Ok([string]$msg) { $lines.Add('OK: ' + $msg) }
function Add-Info([string]$msg) { $lines.Add('INFO: ' + $msg) }

$exitCode = 0
try {
    if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Write-Output 'INFO: Microsoft Defender cmdlets are not available (not applicable)'
        exit 3
    }
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Output 'INFO: Microsoft Defender service (WinDefend) is not installed (not applicable)'
        exit 3
    }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        if ($svc.Status -ne 'Running') {
            Write-Output ('INFO: Microsoft Defender is not running (service {0}); probably replaced by another antivirus' -f $svc.Status)
            exit 3
        }
        throw
    }

    $mode = 'Normal'
    if ($st.PSObject.Properties['AMRunningMode'] -and $st.AMRunningMode) { $mode = [string]$st.AMRunningMode }
    $passive = ($mode -match 'Passive|EDR')
    $lines.Add(("INFO: running mode {0}, product {1}, engine {2}" -f $mode, $st.AMProductVersion, $st.AMEngineVersion))

    if ($mode -match 'Not running') { Add-Fail 'Defender reports running mode Not running' }
    if ($passive) {
        if ($AllowPassive) { Add-Ok "$mode accepted (-AllowPassive)" }
        else { Add-Fail "Defender is in $mode, another product is primary (use -AllowPassive to accept)" }
    }

    if ($st.AMServiceEnabled) { Add-Ok 'antimalware service enabled' } else { Add-Fail 'antimalware service disabled' }
    if (-not $passive) {
        if ($st.AntivirusEnabled) { Add-Ok 'antivirus enabled' } else { Add-Fail 'antivirus disabled' }
        if ($st.RealTimeProtectionEnabled) { Add-Ok 'real-time protection on' } else { Add-Fail 'real-time protection off' }
    } else {
        Add-Info ("antivirus enabled {0}, real-time protection {1} (passive mode)" -f $st.AntivirusEnabled, $st.RealTimeProtectionEnabled)
    }

    if ($st.PSObject.Properties['IsTamperProtected'] -and $null -ne $st.IsTamperProtected) {
        if ($st.IsTamperProtected) { Add-Ok 'tamper protection on' } else { Add-Warn 'tamper protection off' }
    } else {
        Add-Info 'tamper protection state not reported by this Defender version'
    }

    $age = $null
    if ($st.AntivirusSignatureLastUpdated -and ([datetime]$st.AntivirusSignatureLastUpdated).Year -gt 2000) {
        $age = [math]::Floor(((Get-Date) - [datetime]$st.AntivirusSignatureLastUpdated).TotalDays)
        if ($age -lt 0) { $age = 0 }
    }
    if ($null -eq $age) {
        Add-Warn ('signature date unknown (version {0})' -f $st.AntivirusSignatureVersion)
    } else {
        $sig = "signatures {0}, updated {1} ({2} days ago, limit {3})" -f $st.AntivirusSignatureVersion,
               ([datetime]$st.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd HH:mm'), $age, $MaxSignatureAgeDays
        if ($age -gt $MaxSignatureAgeDays) { Add-Warn $sig } else { Add-Ok $sig }
    }

    if ($script:isFail) { $exitCode = 1; Write-Output 'FAIL: Microsoft Defender is not protecting this machine' }
    elseif ($script:isWarn) { $exitCode = 2; Write-Output 'WARN: Microsoft Defender needs attention' }
    else { Write-Output 'OK: Microsoft Defender is protecting this machine' }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
