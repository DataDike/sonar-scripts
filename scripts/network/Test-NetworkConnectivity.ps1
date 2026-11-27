#Requires -Version 5.1
<#
.SYNOPSIS
    Checks active network adapters, gateway reachability, DNS resolution and a TCP connection.

.DESCRIPTION
    Lists the active adapters (status Up with an IPv4 address): name, link speed, IPv4 address,
    prefix length, default gateway and DNS servers. Then pings each default gateway, resolves
    -DnsName and opens a TCP connection to -Target:-Port, reporting the latency in milliseconds.
    Read-only: nothing is changed. Use as a script check (exit code drives the alert) or on demand
    when a user reports "no internet".

.PARAMETER DnsName
    Name to resolve through the configured DNS servers. Default www.microsoft.com.

.PARAMETER Target
    Host name or address for the TCP test. Default: the value of -DnsName.

.PARAMETER Port
    TCP port for the connection test. Default 443.

.PARAMETER TimeoutMs
    Timeout of the TCP connection in milliseconds. Default 3000.

.EXAMPLE
    -DnsName www.microsoft.com -Port 443

.EXAMPLE
    -Target fileserver.contoso.local -Port 445 -TimeoutMs 2000

.NOTES
    Name:       Network - Test connectivity
    GUID:       d3b7cd54-562d-4b8c-ba65-2a9d6dc230b5
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator not required)
    Exit codes: 0 OK | 1 FAIL (no active adapter, DNS or TCP failure) | 2 WARN (gateway does not answer ping)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [string]$DnsName = 'www.microsoft.com',
    [string]$Target,
    [ValidateRange(1, 65535)]
    [int]$Port = 443,
    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 3000
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

if (-not $Target) { $Target = $DnsName }

$lines = New-Object System.Collections.Generic.List[string]
$fails = New-Object System.Collections.Generic.List[string]
$warns = New-Object System.Collections.Generic.List[string]
$exitCode = 0

try {
    # --- Active adapters -------------------------------------------------------------------
    $configs = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
            $_.NetAdapter -and $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address
        })
    if ($configs.Count -eq 0) {
        $fails.Add('no active network adapter with an IPv4 address') | Out-Null
    }

    $gateways = New-Object System.Collections.Generic.List[string]
    foreach ($c in $configs) {
        $ip = @($c.IPv4Address)[0]
        $gw = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop } | Where-Object { $_ -and $_ -ne '0.0.0.0' })
        $dns = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
        $lines.Add(('INFO: adapter "{0}" speed {1} ip {2}/{3} gateway {4} dns {5}' -f $c.InterfaceAlias,
                $c.NetAdapter.LinkSpeed, $ip.IPAddress, $ip.PrefixLength,
                ($(if ($gw.Count) { $gw -join ',' } else { 'none' })),
                ($(if ($dns.Count) { $dns -join ',' } else { 'none' })))) | Out-Null
        foreach ($g in $gw) { if (-not $gateways.Contains($g)) { $gateways.Add($g) | Out-Null } }
    }

    # --- Gateway ping ----------------------------------------------------------------------
    if ($configs.Count -gt 0 -and $gateways.Count -eq 0) {
        $warns.Add('no default gateway configured') | Out-Null
    }
    foreach ($g in $gateways) {
        $alive = $false
        try { $alive = Test-Connection -ComputerName $g -Count 2 -Quiet -ErrorAction Stop } catch { $alive = $false }
        if ($alive) { $lines.Add("INFO: gateway $g answers ping") | Out-Null }
        else { $warns.Add("gateway $g does not answer ping (ICMP may be blocked)") | Out-Null }
    }

    # --- DNS -------------------------------------------------------------------------------
    if ($configs.Count -gt 0) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $answers = @(Resolve-DnsName -Name $DnsName -DnsOnly -ErrorAction Stop |
                    Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' })
            $sw.Stop()
            if ($answers.Count -eq 0) { $fails.Add("DNS returned no address for $DnsName") | Out-Null }
            else {
                $addrs = @($answers | Select-Object -First 3 | ForEach-Object { $_.IPAddress })
                $lines.Add(('INFO: DNS {0} -> {1} in {2} ms' -f $DnsName, ($addrs -join ','), $sw.ElapsedMilliseconds)) | Out-Null
            }
        }
        catch {
            $fails.Add("DNS resolution of $DnsName failed: " + $_.Exception.Message) | Out-Null
        }

        # --- TCP -----------------------------------------------------------------------------
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $ar = $client.BeginConnect($Target, $Port, $null, $null)
            $done = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            $sw.Stop()
            if ($done) {
                $client.EndConnect($ar)
                $lines.Add(('INFO: TCP {0}:{1} connected in {2} ms' -f $Target, $Port, $sw.ElapsedMilliseconds)) | Out-Null
            }
            else {
                $fails.Add(('TCP {0}:{1} timed out after {2} ms' -f $Target, $Port, $TimeoutMs)) | Out-Null
            }
        }
        catch {
            $msg = $_.Exception.Message
            if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
            $fails.Add(('TCP {0}:{1} failed: {2}' -f $Target, $Port, $msg)) | Out-Null
        }
        finally {
            $client.Close()
        }
    }

    if ($fails.Count) {
        Write-Line ('FAIL: ' + ($fails -join '; '))
        $exitCode = 1
    }
    elseif ($warns.Count) {
        Write-Line ('WARN: ' + ($warns -join '; '))
        $exitCode = 2
    }
    else {
        Write-Line ('OK: network reachable ({0} active adapter(s), DNS and TCP {1}:{2} working)' -f $configs.Count, $Target, $Port)
    }
    $lines | Select-Object -First 25 | ForEach-Object { Write-Line $_ }
}
catch {
    Write-Line ('FAIL: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
