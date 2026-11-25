#Requires -Version 5.1
<#
.SYNOPSIS
    One line: what the script checks or does.

.DESCRIPTION
    A few lines: what it reads or changes, what it never touches, and when to use it
    as a check (exit code drives the alert) or as an action (run on demand / task).

.PARAMETER Threshold
    Describe every parameter, its unit and its default.

.PARAMETER DryRun
    Destructive scripts only: report what would change without changing anything.
    Default is $true; pass -DryRun:$false to apply.

.EXAMPLE
    -Threshold 10

.NOTES
    Name:       Category - Short name
    GUID:       00000000-0000-0000-0000-000000000000
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
    [int]$Threshold = 10,
    [switch]$DryRun = $true
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$exitCode = 0
try {
    # ... collect / act ...
    Write-Output "OK: everything is fine"
}
catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode
