#Requires -Version 5.1
<#
.SYNOPSIS
    Short hardware report: model, serial, BIOS, CPU, memory, disks, TPM and OS.

.DESCRIPTION
    Reads CIM classes only (Win32_ComputerSystem, Win32_BIOS, Win32_Processor,
    Win32_OperatingSystem, Win32_LogicalDisk, MSFT_Partition, MSFT_PhysicalDisk and Win32_Tpm).
    Changes nothing. Use it as an on-demand action or a scheduled inventory task.
    TPM details need administrator rights (the agent runs as SYSTEM); without them the TPM
    line says the state is unknown. Always exits 0 unless an unexpected error happens.

.EXAMPLE
    (no parameters)

.NOTES
    Name:       Inventory - Hardware summary
    GUID:       c0492467-6226-46fa-a308-8b37090d54e8
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (unexpected error)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

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

function ConvertTo-GB([double]$Bytes) {
    return [math]::Round($Bytes / 1GB, 1)
}

function Get-MediaTypeName([int]$Code) {
    switch ($Code) {
        3 { return 'HDD' }
        4 { return 'SSD' }
        5 { return 'SCM' }
        default { return 'unknown media' }
    }
}

$exitCode = 0
try {
    $lines = New-Object System.Collections.Generic.List[string]

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpus = @(Get-CimInstance -ClassName Win32_Processor)

    $lines.Add(("INFO: Model: {0} {1}" -f (ConvertTo-AsciiText $cs.Manufacturer), (ConvertTo-AsciiText $cs.Model)))
    $lines.Add(("INFO: Serial number: {0}" -f (ConvertTo-AsciiText $bios.SerialNumber)))
    $biosDate = if ($bios.ReleaseDate) { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } else { 'unknown date' }
    $lines.Add(("INFO: BIOS: {0} ({1})" -f (ConvertTo-AsciiText $bios.SMBIOSBIOSVersion), $biosDate))

    if ($cpus.Count -gt 0) {
        $cores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
        $threads = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $lines.Add(("INFO: CPU: {0} x {1} ({2} cores, {3} threads)" -f $cpus.Count, (ConvertTo-AsciiText $cpus[0].Name), $cores, $threads))
    }
    $lines.Add(("INFO: RAM: {0} GB" -f (ConvertTo-GB ([double]$cs.TotalPhysicalMemory))))

    # Map drive letters to physical disk media type (best effort; Storage namespace may be absent)
    $mediaByDisk = @{}
    $diskByLetter = @{}
    try {
        foreach ($pd in @(Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName MSFT_PhysicalDisk)) {
            $mediaByDisk[[string]$pd.DeviceId] = Get-MediaTypeName ([int]$pd.MediaType)
        }
        foreach ($part in @(Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName MSFT_Partition)) {
            $letter = [string]$part.DriveLetter
            if ($letter -and $letter.Trim() -and [int][char]$letter[0] -ne 0) {
                $diskByLetter[$letter.Substring(0, 1).ToUpper()] = [string]$part.DiskNumber
            }
        }
    }
    catch {
        $lines.Add("INFO: Disk media type not available on this system")
    }

    foreach ($ld in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
        $letter = ([string]$ld.DeviceID).Substring(0, 1).ToUpper()
        $media = 'unknown media'
        if ($diskByLetter.ContainsKey($letter) -and $mediaByDisk.ContainsKey($diskByLetter[$letter])) {
            $media = $mediaByDisk[$diskByLetter[$letter]]
        }
        $size = [double]$ld.Size
        $free = [double]$ld.FreeSpace
        $pct = if ($size -gt 0) { [math]::Round(100 * $free / $size, 0) } else { 0 }
        $lines.Add(("INFO: Disk {0} {1} GB, {2} GB free ({3}%), {4}" -f $ld.DeviceID, (ConvertTo-GB $size), (ConvertTo-GB $free), $pct, $media))
    }

    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm
        if ($null -eq $tpm) {
            $lines.Add("INFO: TPM: not present")
        }
        else {
            $spec = ([string]$tpm.SpecVersion).Split(',')[0].Trim()
            $ready = 'unknown'
            try {
                $r = Invoke-CimMethod -InputObject $tpm -MethodName IsReady
                $ready = [string]$r.IsReady
            }
            catch {
                $ready = 'unknown'
            }
            $lines.Add(("INFO: TPM: present, version {0}, enabled {1}, activated {2}, ready {3}" -f $spec, $tpm.IsEnabled_InitialValue, $tpm.IsActivated_InitialValue, $ready))
        }
    }
    catch {
        $lines.Add("INFO: TPM: state unknown (needs administrator rights or TPM provider missing)")
    }

    $lines.Add(("INFO: OS: {0} {1}, build {2}.{3}" -f (ConvertTo-AsciiText $os.Caption), (ConvertTo-AsciiText $os.OSArchitecture), $os.BuildNumber, (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR))
    $displayVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
    if ($displayVersion) { $lines.Add(("INFO: OS version: {0}" -f $displayVersion)) }

    Write-Output ("OK: hardware summary collected ({0} {1})" -f (ConvertTo-AsciiText $cs.Manufacturer), (ConvertTo-AsciiText $cs.Model))
    $lines | ForEach-Object { Write-Output $_ }
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
