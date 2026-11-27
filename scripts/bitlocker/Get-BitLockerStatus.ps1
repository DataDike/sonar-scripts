#Requires -Version 5.1
<#
.SYNOPSIS
    Reports BitLocker protection of every fixed volume.

.DESCRIPTION
    Read-only. For each operating system and fixed data volume (Win32_EncryptableVolume, namespace
    root\cimv2\Security\MicrosoftVolumeEncryption) it reports protection status, conversion status
    and percentage, encryption method and the TYPES of key protectors (TPM, RecoveryPassword...).
    Recovery passwords and key protector ids are never read or printed. Removable drives are ignored.

    Verdict rules:
      FAIL (1) the OS volume is not protected (off, suspended or decrypting); with
               -RequireOsVolumeOnly:$false, also any unprotected fixed data volume;
               or BitLocker could not be read (for example access denied).
      WARN (2) a fixed data volume is unprotected (default mode), or any volume is encrypting
               or paused (an OS volume still encrypting is WARN, not FAIL).
      N/A  (3) BitLocker is not available (for example Windows Home edition) or no fixed volume.
      OK   (0) every fixed volume is protected.

.PARAMETER RequireOsVolumeOnly
    Default $true: only the OS volume can make the check FAIL; unprotected data volumes are WARN.
    Pass -RequireOsVolumeOnly:$false to make unprotected data volumes FAIL too.

.EXAMPLE
    -RequireOsVolumeOnly:$false

.NOTES
    Name:       BitLocker - Volume status
    GUID:       e8887da9-3605-4005-a4bc-1520ae86b2ac
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
    [switch]$RequireOsVolumeOnly = $true
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ns = 'root\cimv2\Security\MicrosoftVolumeEncryption'
$conversionNames = @('fully decrypted', 'fully encrypted', 'encrypting', 'decrypting', 'encryption paused', 'decryption paused')
$methodNames = @('None', 'AES-128 with diffuser', 'AES-256 with diffuser', 'AES-128', 'AES-256', 'Hardware', 'XTS-AES-128', 'XTS-AES-256')
$protectorNames = @('Unknown', 'TPM', 'ExternalKey', 'RecoveryPassword', 'TPM+PIN', 'TPM+StartupKey',
                    'TPM+PIN+StartupKey', 'PublicKey', 'Passphrase', 'TPMCertificate', 'CNG-SID')

function Get-Name($list, $index) {
    if ($null -ne $index -and [int]$index -ge 0 -and [int]$index -lt $list.Count) { return $list[[int]$index] }
    return ('code ' + $index)
}

$lines = New-Object System.Collections.Generic.List[string]
$script:isFail = $false
$script:isWarn = $false

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

    # VolumeType: 0 = OS, 1 = fixed data, 2 = removable
    $fixed = @($volumes | Where-Object { $_.VolumeType -eq 0 -or $_.VolumeType -eq 1 })
    if ($fixed.Count -eq 0) {
        Write-Output 'INFO: no fixed volume reported by BitLocker'
        $host.SetShouldExit(3); exit 3
    }

    $osProtected = $null
    foreach ($v in ($fixed | Sort-Object -Property VolumeType, DriveLetter)) {
        $isOs = ($v.VolumeType -eq 0)
        $label = if ($v.DriveLetter) { $v.DriveLetter } else { '(no letter)' }
        $role = if ($isOs) { 'OS' } else { 'data' }

        $prot = (Invoke-CimMethod -InputObject $v -MethodName GetProtectionStatus).ProtectionStatus
        $conv = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus
        $method = (Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod).EncryptionMethod
        $types = New-Object System.Collections.Generic.List[string]
        $ids = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID)
        foreach ($id in $ids) {
            if (-not $id) { continue }
            $t = (Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $id }).KeyProtectorType
            $types.Add((Get-Name $protectorNames $t))
        }
        $typeText = if ($types.Count) { ($types | Sort-Object -Unique) -join ',' } else { 'none' }
        $convText = Get-Name $conversionNames $conv.ConversionStatus
        $protText = switch ([int]$prot) { 0 { 'off' } 1 { 'on' } 2 { 'unknown (locked)' } default { "code $prot" } }
        if ([int]$prot -eq 0 -and [int]$conv.ConversionStatus -eq 1) { $protText = 'off (suspended)' }

        $detail = "{0} {1}: protection {2}, {3} {4}%, method {5}, protectors {6}" -f $role, $label, $protText,
                  $convText, $conv.EncryptionPercentage, (Get-Name $methodNames $method), $typeText

        $inProgress = ([int]$conv.ConversionStatus -eq 2 -or [int]$conv.ConversionStatus -eq 4)
        $protected = ([int]$prot -eq 1)
        if ($isOs) { $osProtected = $protected }

        if ($protected -and -not $inProgress) { $lines.Add('OK: ' + $detail) }
        elseif ($inProgress) { $script:isWarn = $true; $lines.Add('WARN: ' + $detail) }
        elseif ($isOs -or -not $RequireOsVolumeOnly) { $script:isFail = $true; $lines.Add('FAIL: ' + $detail) }
        else { $script:isWarn = $true; $lines.Add('WARN: ' + $detail) }
    }
    if ($null -eq $osProtected) { $lines.Add('INFO: no OS volume reported by BitLocker') }

    if ($script:isFail) { $exitCode = 1; Write-Output 'FAIL: BitLocker protection is missing on a required volume' }
    elseif ($script:isWarn) { $exitCode = 2; Write-Output 'WARN: BitLocker is incomplete on some volume' }
    else { Write-Output 'OK: every fixed volume is protected by BitLocker' }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
