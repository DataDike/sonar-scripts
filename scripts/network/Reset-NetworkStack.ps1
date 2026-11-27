#Requires -Version 5.1
<#
.SYNOPSIS
    Flushes the DNS cache and optionally resets Winsock and the TCP/IP stack.

.DESCRIPTION
    Always flushes the DNS client cache (ipconfig /flushdns). With -ResetWinsock it runs
    "netsh winsock reset" and with -ResetTcpIp it runs "netsh int ip reset"; both need a reboot to
    take effect. The machine is rebooted only when -AllowReboot is also passed; otherwise the script
    reports that a reboot is required (exit 2). Static IP settings are kept by Windows but a TCP/IP
    reset can drop custom stack tuning, and a Winsock reset removes third-party LSP entries (some
    VPN or security agents need a repair afterwards).
    Default is a dry run that only prints the plan. Run on demand as an action, not as a check.

.PARAMETER ResetWinsock
    Also reset the Winsock catalog (netsh winsock reset). Needs a reboot.

.PARAMETER ResetTcpIp
    Also reset the TCP/IP stack (netsh int ip reset). Needs a reboot.

.PARAMETER AllowReboot
    Reboot the machine at the end when a reset was applied. Without it nothing is rebooted.

.PARAMETER DryRun
    Report what would be done without changing anything. Default is $true; pass -DryRun:$false to apply.

.EXAMPLE
    -DryRun:$false

.EXAMPLE
    -ResetWinsock -ResetTcpIp -DryRun:$false -AllowReboot

.NOTES
    Name:       Network - Reset network stack
    GUID:       e3a123df-89a9-4905-8d70-9f938bc4705b
    Version:    1.0.0
    Author:     DataDike
    License:    MIT
    Platforms:  windows
    Context:    SYSTEM (administrator)
    Exit codes: 0 OK | 1 FAIL | 2 WARN (reboot required)
    Changelog:
        1.0.0 (2026-11-24) First release.

.LINK
    https://github.com/DataDike/sonar-scripts
#>
[CmdletBinding()]
param(
    [switch]$ResetWinsock,
    [switch]$ResetTcpIp,
    [switch]$AllowReboot,
    [switch]$DryRun = $true
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Output is ASCII only: strip accents and any other non-ASCII character (localized OS messages).
function Write-Line([string]$Text) {
    $n = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    Write-Output ([regex]::Replace($n, '[^\x20-\x7E]', ''))
}

function Invoke-NativeStep {
    param([string]$Label, [string]$FilePath, [string[]]$Arguments)
    $out = & $FilePath @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $text = ($out -replace '\s+', ' ').Trim()
        if ($text.Length -gt 200) { $text = $text.Substring(0, 200) }
        throw ("{0} failed with exit code {1}: {2}" -f $Label, $code, $text)
    }
}

$exitCode = 0
try {
    $plan = New-Object System.Collections.Generic.List[string]
    $plan.Add('flush DNS cache (ipconfig /flushdns)') | Out-Null
    if ($ResetWinsock) { $plan.Add('reset Winsock catalog (netsh winsock reset)') | Out-Null }
    if ($ResetTcpIp) { $plan.Add('reset TCP/IP stack (netsh int ip reset)') | Out-Null }
    $needsReboot = ($ResetWinsock -or $ResetTcpIp)

    if ($DryRun) {
        Write-Line ('OK: dry run, nothing changed; plan: ' + ($plan -join '; '))
        if ($needsReboot) {
            if ($AllowReboot) { Write-Line 'INFO: would reboot the machine afterwards (-AllowReboot)' }
            else { Write-Line 'INFO: a reboot would be required afterwards (pass -AllowReboot to reboot automatically)' }
        }
        Write-Line 'INFO: pass -DryRun:$false to apply'
        $host.SetShouldExit(0); exit 0
    }

    $sys32 = Join-Path $env:SystemRoot 'System32'
    $done = New-Object System.Collections.Generic.List[string]

    Invoke-NativeStep -Label 'ipconfig /flushdns' -FilePath (Join-Path $sys32 'ipconfig.exe') -Arguments @('/flushdns')
    $done.Add('DNS cache flushed') | Out-Null

    if ($ResetWinsock) {
        Invoke-NativeStep -Label 'netsh winsock reset' -FilePath (Join-Path $sys32 'netsh.exe') -Arguments @('winsock', 'reset')
        $done.Add('Winsock catalog reset') | Out-Null
    }
    if ($ResetTcpIp) {
        Invoke-NativeStep -Label 'netsh int ip reset' -FilePath (Join-Path $sys32 'netsh.exe') -Arguments @('int', 'ip', 'reset')
        $done.Add('TCP/IP stack reset') | Out-Null
    }

    if ($needsReboot) {
        if ($AllowReboot) {
            Write-Line ('OK: ' + ($done -join '; ') + '; rebooting now')
            if ($AllowReboot) { Restart-Computer -Force }   # only with -AllowReboot
            $exitCode = 0
        }
        else {
            Write-Line ('WARN: reboot required to complete the reset (' + ($done -join '; ') + ')')
            Write-Line 'INFO: pass -AllowReboot to reboot automatically, or reboot in a maintenance window'
            $exitCode = 2
        }
    }
    else {
        Write-Line ('OK: ' + ($done -join '; '))
    }
}
catch {
    Write-Line ('FAIL: ' + $_.Exception.Message)
    $exitCode = 1
}
$host.SetShouldExit($exitCode); exit $exitCode
