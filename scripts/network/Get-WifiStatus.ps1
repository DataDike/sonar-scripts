#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the Wi-Fi connection: SSID, BSSID, radio type, band, channel, signal and link rates.

.DESCRIPTION
    Parses "netsh wlan show interfaces". Windows prints localized labels, so fields are found by
    the shape of their value first and by label only when needed:
      SSID           label "SSID" (same in every language)
      BSSID          label containing "BSSID", else the second MAC address of the interface
      radio type     value starting with 802.11
      band           value like "5 GHz" (Windows 11); otherwise derived from the channel
      channel        label Channel / Canal / Kanal
      signal         value like "87%"
      receive/transm the two lines whose label contains "(Mbps)", in that order
    An interface is "connected" when an SSID line is present. Saved profiles and their keys are
    never read. Limits: on languages whose channel label is not in the list, the channel and the
    derived band are reported as unknown.
    Read only. Use it as a check: exits 3 on machines without Wi-Fi (desktops, servers).

.PARAMETER MinSignal
    Minimum signal quality in percent; below it the result is a warning. Default 50.

.EXAMPLE
    -MinSignal 50

.NOTES
    Name:       Network - Wi-Fi status
    GUID:       bf3fb894-0bfe-4279-b20f-d7992115971a
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL (Wi-Fi adapter present but not connected, or error) |
                2 WARN (signal below -MinSignal) | 3 NOT APPLICABLE (no Wi-Fi adapter / WLAN service)
    Changelog:
        1.0.0 (2026-11-27) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [int]$MinSignal = 50
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-Ascii([string]$Text) {
    if (-not $Text) { return '' }
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    return [regex]::Replace($n, '[^\x20-\x7E]', '')
}

function Write-Report([string]$Verdict, $Lines) {
    $size = $Verdict.Length + 2
    Write-Output $Verdict
    foreach ($l in $Lines) {
        $t = ConvertTo-Ascii $l
        if ($size + $t.Length + 2 -gt 3900) { Write-Output 'INFO: output truncated'; break }
        $size += $t.Length + 2
        Write-Output $t
    }
}

$macRx = '^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$'
$guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$channelLabels = 'channel', 'canal', 'kanal', 'canale'

# Turns one interface block (lines "label : value") into an object
function ConvertTo-WifiInterface($Pairs) {
    $w = [pscustomobject]@{
        Name = ''; Ssid = ''; Bssid = ''; Radio = ''; Band = ''; Channel = $null
        Signal = $null; RxMbps = ''; TxMbps = ''; Connected = $false
    }
    if ($Pairs.Count -gt 0) { $w.Name = $Pairs[0].Value }
    $macs = 0
    $rates = 0
    foreach ($p in $Pairs) {
        $k = $p.Key
        $v = $p.Value
        if ($k -eq 'ssid') { $w.Ssid = $v; $w.Connected = $true; continue }
        if ($v -match $macRx) {
            $macs++
            if ($k -match 'bssid' -or ($macs -eq 2 -and -not $w.Bssid)) { $w.Bssid = $v.ToLowerInvariant() }
            continue
        }
        if ($v -match '^802\.11') { $w.Radio = $v; continue }
        if ($v -match '^\d+(\.\d+)?\s*GHz$') { $w.Band = $v; continue }
        if ($v -match '^(\d{1,3})\s*%$') { $w.Signal = [int]$Matches[1]; continue }
        if ($k -match '\(mbps\)') {
            $rates++
            if ($rates -eq 1) { $w.RxMbps = $v } elseif ($rates -eq 2) { $w.TxMbps = $v }
            continue
        }
        if (($channelLabels -contains $k) -and $v -match '^\d+$') { $w.Channel = [int]$v }
    }
    if (-not $w.Band -and $w.Channel) {
        if ($w.Channel -le 14) { $w.Band = '2.4 GHz' } else { $w.Band = '5 GHz (derived from channel)' }
    }
    return $w
}

$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    $wlan = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
    $adapters = @()
    try {
        $adapters = @(Get-CimInstance -Namespace root\StandardCimv2 -ClassName MSFT_NetAdapter -ErrorAction Stop |
                Where-Object { $_.NdisPhysicalMedium -eq 9 -and $_.HardwareInterface })
    }
    catch { $adapters = @() }

    if (-not $wlan) {
        Write-Output 'INFO: NOT APPLICABLE: WLAN AutoConfig service is not installed (no Wi-Fi on this machine)'
        $host.SetShouldExit(3); exit 3
    }
    if ($wlan.Status -ne 'Running') {
        if ($adapters.Count -eq 0) {
            Write-Output 'INFO: NOT APPLICABLE: no Wi-Fi adapter and WLAN AutoConfig is not running'
            $host.SetShouldExit(3); exit 3
        }
        Write-Output ("FAIL: Wi-Fi adapter present ({0}) but the WLAN AutoConfig service is {1}" -f (ConvertTo-Ascii $adapters[0].InterfaceDescription), $wlan.Status)
        $host.SetShouldExit(1); exit 1
    }

    $out = @(& netsh.exe wlan show interfaces 2>&1 | ForEach-Object { [string]$_ })
    # Split into blocks separated by blank lines; an interface block has a GUID line
    $blocks = New-Object System.Collections.Generic.List[object]
    $cur = New-Object System.Collections.Generic.List[object]
    foreach ($l in ($out + '')) {
        if (-not $l.Trim()) {
            if ($cur.Count -gt 0) { $blocks.Add($cur); $cur = New-Object System.Collections.Generic.List[object] }
            continue
        }
        $m = [regex]::Match($l, '^\s+(.+?)\s*:\s(.*)$')
        if ($m.Success) {
            $key = (ConvertTo-Ascii $m.Groups[1].Value).Trim().ToLowerInvariant()
            $cur.Add([pscustomobject]@{ Key = $key; Value = $m.Groups[2].Value.Trim() })
        }
    }
    $ifaces = @($blocks | Where-Object { @($_ | Where-Object { $_.Value -match $guidRx }).Count -gt 0 } |
            ForEach-Object { ConvertTo-WifiInterface $_ })

    if ($ifaces.Count -eq 0) {
        if ($adapters.Count -gt 0) {
            Write-Output ("FAIL: Wi-Fi adapter present ({0}) but no wireless interface is available (disabled?)" -f (ConvertTo-Ascii $adapters[0].InterfaceDescription))
            $host.SetShouldExit(1); exit 1
        }
        Write-Output 'INFO: NOT APPLICABLE: no wireless interface on this machine'
        $host.SetShouldExit(3); exit 3
    }

    $connected = @($ifaces | Where-Object { $_.Connected })
    foreach ($w in $ifaces) {
        if (-not $w.Connected) { $lines.Add(("INFO: {0}: not connected" -f $w.Name)); continue }
        $sig = 'unknown'
        if ($null -ne $w.Signal) { $sig = '{0}%' -f $w.Signal }
        $ch = 'unknown'
        if ($w.Channel) { $ch = [string]$w.Channel }
        $band = $w.Band
        if (-not $band) { $band = 'unknown' }
        $lines.Add(("INFO: {0}: SSID '{1}', BSSID {2}" -f $w.Name, $w.Ssid, $w.Bssid))
        $lines.Add(("INFO: {0}: radio {1}, band {2}, channel {3}, signal {4}, receive {5} Mbps, transmit {6} Mbps" -f $w.Name, $w.Radio, $band, $ch, $sig, $w.RxMbps, $w.TxMbps))
    }

    if ($connected.Count -eq 0) {
        $exitCode = 1
        $verdict = "FAIL: Wi-Fi adapter present but not connected ({0} interface(s))" -f $ifaces.Count
    }
    else {
        $best = $connected | Sort-Object -Property Signal -Descending | Select-Object -First 1
        if ($null -ne $best.Signal -and $best.Signal -lt $MinSignal) {
            $exitCode = 2
            $verdict = "WARN: Wi-Fi signal {0}% on '{1}' is below {2}%" -f $best.Signal, $best.Ssid, $MinSignal
        }
        elseif ($null -eq $best.Signal) {
            $exitCode = 2
            $verdict = "WARN: connected to '{0}' but the signal could not be read" -f $best.Ssid
        }
        else {
            $verdict = "OK: connected to '{0}', signal {1}% ({2}, {3})" -f $best.Ssid, $best.Signal, $best.Radio, $best.Band
        }
    }
    Write-Report (ConvertTo-Ascii $verdict) $lines
}
catch {
    Write-Report ('FAIL: ' + $_.Exception.Message) $lines
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
