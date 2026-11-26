#Requires -Version 5.1
<#
.SYNOPSIS
    Checks TPM 2.0 readiness, firmware type (UEFI or legacy BIOS) and Secure Boot.

.DESCRIPTION
    Read-only check. It reads:
      - the TPM from Win32_Tpm (namespace root\cimv2\Security\MicrosoftTpm): present, enabled,
        activated, owned and specification version;
      - the firmware type from $env:firmware_type, or the registry value PEFirmwareType;
      - Secure Boot from Confirm-SecureBootUEFI, or the registry value UEFISecureBootEnabled.

    Verdict rules:
      FAIL (1) no TPM, TPM older than 2.0, TPM not enabled or not activated, TPM not readable
               (for example access denied), or UEFI firmware with Secure Boot off.
      WARN (2) legacy BIOS boot with a ready TPM 2.0: Secure Boot is impossible until the disk
               is converted to GPT and the firmware switched to UEFI. Also WARN when the TPM is
               ready but the Secure Boot state cannot be read.
      N/A  (3) legacy BIOS boot and no TPM at all: the hardware (or a generation 1 virtual
               machine) cannot meet the requirement; replacing it is not a configuration fix.
      OK   (0) TPM 2.0 enabled and activated, UEFI and Secure Boot on.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       BitLocker - TPM and Secure Boot
    GUID:       05ac476b-74f1-465a-9488-fb5d1df051af
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
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$lines = New-Object System.Collections.Generic.List[string]

$exitCode = 0
try {
    # 1. Firmware type
    $firmware = 'unknown'
    if ($env:firmware_type) {
        if ($env:firmware_type -match 'UEFI') { $firmware = 'UEFI' } elseif ($env:firmware_type -match 'Legacy|BIOS') { $firmware = 'BIOS' }
    }
    if ($firmware -eq 'unknown') {
        try {
            $pe = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop).PEFirmwareType
            if ($pe -eq 2) { $firmware = 'UEFI' } elseif ($pe -eq 1) { $firmware = 'BIOS' }
        } catch { $null = $_ }
    }
    $lines.Add('INFO: firmware type ' + $firmware)

    # 2. Secure Boot (only meaningful on UEFI)
    $secureBoot = $null
    $sbSource = ''
    if ($firmware -ne 'BIOS') {
        try {
            $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
            $sbSource = 'firmware'
        } catch {
            if ($_.Exception -is [System.PlatformNotSupportedException] -or $_.Exception.Message -match 'not supported') {
                if ($firmware -eq 'unknown') { $firmware = 'BIOS' }
            }
        }
        if ($null -eq $secureBoot -and $firmware -ne 'BIOS') {
            try {
                $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop).UEFISecureBootEnabled
                $secureBoot = ($v -eq 1)
                $sbSource = 'registry'
            } catch { $null = $_ }
        }
    }

    # 3. TPM
    $tpm = $null; $tpmError = $null
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
    } catch {
        $code = ''
        if ($_.Exception.PSObject.Properties['NativeErrorCode']) { $code = [string]$_.Exception.NativeErrorCode }
        if ($code -match 'AccessDenied' -or $_.Exception.Message -match 'Access (is )?denied') { $tpmError = 'access denied (run as SYSTEM or administrator)' }
        elseif ($code -match 'InvalidNamespace|InvalidClass') { $tpm = $null }
        else { $tpmError = $_.Exception.Message.Trim() }
    }

    $fail = New-Object System.Collections.Generic.List[string]
    $tpmReady = $false
    $tpmAbsent = $false
    if ($tpmError) {
        $fail.Add('TPM not readable: ' + $tpmError)
    } elseif (-not $tpm) {
        $tpmAbsent = $true
        $lines.Add('INFO: no TPM found')
    } else {
        $spec = ([string]$tpm.SpecVersion).Split(',')[0].Trim()
        $major = 0
        [void][int]::TryParse(($spec.Split('.')[0]), [ref]$major)
        $lines.Add(("INFO: TPM spec {0}, enabled {1}, activated {2}, owned {3}" -f $spec, $tpm.IsEnabled_InitialValue, $tpm.IsActivated_InitialValue, $tpm.IsOwned_InitialValue))
        if ($major -lt 2) { $fail.Add("TPM version $spec is older than 2.0") }
        if (-not $tpm.IsEnabled_InitialValue) { $fail.Add('TPM is not enabled') }
        if (-not $tpm.IsActivated_InitialValue) { $fail.Add('TPM is not activated') }
        if ($major -ge 2 -and $tpm.IsEnabled_InitialValue -and $tpm.IsActivated_InitialValue) { $tpmReady = $true }
    }

    if ($firmware -eq 'BIOS') {
        $lines.Add('INFO: legacy BIOS boot: Secure Boot is not available')
        if ($tpmAbsent) {
            Write-Output 'INFO: legacy BIOS without TPM: hardware cannot meet TPM 2.0 / Secure Boot (not applicable)'
            $lines | ForEach-Object { Write-Output $_ }
            exit 3
        }
    } elseif ($null -eq $secureBoot) {
        $lines.Add('INFO: Secure Boot state unknown (not readable)')
    } else {
        $lines.Add(("INFO: Secure Boot {0} (source {1})" -f $(if ($secureBoot) { 'on' } else { 'off' }), $sbSource))
        if ($firmware -eq 'UEFI' -and -not $secureBoot) { $fail.Add('Secure Boot is off on UEFI firmware') }
    }
    if ($tpmAbsent) { $fail.Add('no TPM found') }

    if ($fail.Count -gt 0) {
        $exitCode = 1
        Write-Output ('FAIL: ' + ($fail -join '; '))
    } elseif ($firmware -eq 'BIOS') {
        $exitCode = 2
        Write-Output 'WARN: TPM 2.0 ready but the machine boots in legacy BIOS mode (no Secure Boot)'
    } elseif ($tpmReady -and $secureBoot) {
        Write-Output 'OK: TPM 2.0 ready and Secure Boot on'
    } else {
        $exitCode = 2
        Write-Output 'WARN: TPM 2.0 ready but Secure Boot state could not be confirmed'
    }
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
