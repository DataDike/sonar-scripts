#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that the OS volume has a BitLocker recovery password and that it was backed up.

.DESCRIPTION
    Read-only check. It counts the RecoveryPassword (numerical password) key protectors of the
    operating system volume and looks for evidence that the recovery information was backed up,
    in the event log 'Microsoft-Windows-BitLocker/BitLocker Management' (provider BitLocker-API):
      845 = recovery information backed up to Microsoft Entra ID (Azure AD)
      784 = recovery information backed up to Active Directory Domain Services
      846 = backup to Microsoft Entra ID failed (reported as INFO only)
    The event ids are best effort: they are the ones documented for current Windows 10/11 builds,
    the event text is localized, and old events may have been overwritten by log rotation.
    The recovery password and the key protector ids are never read or printed.

    Verdict rules:
      FAIL (1) the OS volume has no RecoveryPassword protector, or BitLocker could not be read.
      WARN (2) a RecoveryPassword exists but no backup event was found within -LookbackDays.
      N/A  (3) BitLocker is not available, or the OS volume is not encrypted and has no protector
               (use 'BitLocker - Volume status' to alert on unencrypted volumes).
      OK   (0) a RecoveryPassword exists and a backup event was found.

.PARAMETER LookbackDays
    How many days of the event log to search for backup events. Default 3650.

.EXAMPLE
    -LookbackDays 365

.NOTES
    Name:       BitLocker - Recovery key backup
    GUID:       94343065-0a30-4617-8759-a28c55fcc5bb
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL | 2 WARN | 3 NOT APPLICABLE
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$LookbackDays = 3650
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ns = 'root\cimv2\Security\MicrosoftVolumeEncryption'
$logName = 'Microsoft-Windows-BitLocker/BitLocker Management'
$lines = New-Object System.Collections.Generic.List[string]

$exitCode = 0
try {
    try {
        $volumes = @(Get-CimInstance -Namespace $ns -ClassName Win32_EncryptableVolume -ErrorAction Stop)
    } catch {
        $msg = $_.Exception.Message
        $code = ''
        if ($_.Exception.PSObject.Properties['NativeErrorCode']) { $code = [string]$_.Exception.NativeErrorCode }
        if ($code -match 'InvalidNamespace|InvalidClass' -or $msg -match 'Invalid namespace|Invalid class') {
            Write-Output 'INFO: BitLocker is not available on this system (no BitLocker WMI provider, e.g. Home edition)'
            $host.SetShouldExit(3); exit 3
        }
        if ($code -match 'AccessDenied' -or $msg -match 'Access (is )?denied') {
            Write-Output 'FAIL: access denied reading BitLocker status; run as SYSTEM or administrator'
            $host.SetShouldExit(1); exit 1
        }
        throw
    }

    $os = $volumes | Where-Object { $_.VolumeType -eq 0 } | Select-Object -First 1
    if (-not $os) { $os = $volumes | Where-Object { $_.DriveLetter -eq $env:SystemDrive } | Select-Object -First 1 }
    if (-not $os) { Write-Output 'INFO: OS volume not reported by BitLocker'; $host.SetShouldExit(3); exit 3 }
    $drive = if ($os.DriveLetter) { $os.DriveLetter } else { $env:SystemDrive }

    $conv = (Invoke-CimMethod -InputObject $os -MethodName GetConversionStatus).ConversionStatus
    $allIds = @((Invoke-CimMethod -InputObject $os -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID | Where-Object { $_ })
    # KeyProtectorType 3 = numerical password (recovery password); only the count is used
    $rpCount = @((Invoke-CimMethod -InputObject $os -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]3 }).VolumeKeyProtectorID | Where-Object { $_ }).Count

    if ([int]$conv -eq 0 -and $allIds.Count -eq 0) {
        Write-Output ("INFO: OS volume {0} is not encrypted and has no key protector; nothing to back up" -f $drive)
        $host.SetShouldExit(3); exit 3
    }
    if ($rpCount -eq 0) {
        Write-Output ("FAIL: OS volume {0} has no recovery password protector ({1} other protector(s))" -f $drive, $allIds.Count)
        $host.SetShouldExit(1); exit 1
    }
    $lines.Add(("OK: OS volume {0} has {1} recovery password protector(s)" -f $drive, $rpCount))

    # Policy hints (values only, never secrets)
    try {
        $fve = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -ErrorAction Stop
        if ($fve.PSObject.Properties['OSRequireActiveDirectoryBackup']) {
            $lines.Add(('INFO: policy OSRequireActiveDirectoryBackup = {0}' -f $fve.OSRequireActiveDirectoryBackup))
        }
        if ($fve.PSObject.Properties['OSActiveDirectoryBackup']) {
            $lines.Add(('INFO: policy OSActiveDirectoryBackup = {0}' -f $fve.OSActiveDirectoryBackup))
        }
    } catch { $null = $_ }

    # Backup evidence in the event log
    $start = (Get-Date).AddDays(-1 * [math]::Abs($LookbackDays))
    $events = @()
    $logError = $null
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = 784, 845, 846; StartTime = $start } -MaxEvents 200 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $logError = $_.Exception.Message }
    }

    $evidence = $null
    if ($logError) {
        $lines.Add('INFO: BitLocker event log not readable: ' + $logError.Trim())
    } else {
        $ok = @($events | Where-Object { $_.Id -eq 784 -or $_.Id -eq 845 })
        $failed = @($events | Where-Object { $_.Id -eq 846 })
        # Prefer events that name the OS drive; the text is localized, so fall back to any success event
        $forOs = @($ok | Where-Object { $_.Message -and $_.Message -match [regex]::Escape($drive) })
        $pick = if ($forOs.Count) { $forOs } else { $ok }
        $ad = @($pick | Where-Object { $_.Id -eq 784 })
        $entra = @($pick | Where-Object { $_.Id -eq 845 })
        if ($ad.Count) {
            $lines.Add(('OK: backup to Active Directory found (event 784), latest {0}' -f $ad[0].TimeCreated.ToString('yyyy-MM-dd HH:mm')))
            $evidence = $true
        }
        if ($entra.Count) {
            $lines.Add(('OK: backup to Entra ID found (event 845), latest {0}' -f $entra[0].TimeCreated.ToString('yyyy-MM-dd HH:mm')))
            $evidence = $true
        }
        if ($evidence -and -not $forOs.Count) { $lines.Add('INFO: backup events do not name the OS drive (localized text or another volume)') }
        if ($failed.Count) {
            $lines.Add(('INFO: {0} failed backup(s) to Entra ID (event 846), latest {1}' -f $failed.Count, $failed[0].TimeCreated.ToString('yyyy-MM-dd HH:mm')))
        }
    }

    if ($evidence) {
        Write-Output ("OK: OS volume {0} has a recovery password and a backup was recorded" -f $drive)
    } else {
        $exitCode = 2
        Write-Output ("WARN: OS volume {0} has a recovery password but no backup evidence in the last {1} days" -f $drive, $LookbackDays)
    }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
