# Writing a script for the SONAR library

Every script in this repository runs as **SYSTEM on thousands of machines**. Treat each line as
production code. Start from [`templates/script-template.ps1`](templates/script-template.ps1).

## Rules

### Compatibility
- Must run on **Windows PowerShell 5.1** (Windows 10/11, Server 2016+). Start with `#Requires -Version 5.1`.
- No PowerShell 7-only syntax or cmdlets: no `??`, `?:`, `&&`/`||` pipeline chains, `ForEach-Object -Parallel`,
  `-AsHashtable`, `Get-Error`, etc.
- Use `Get-CimInstance`, never `Get-WmiObject` and **never `Win32_Product`** (it triggers an MSI
  repair on every installed product). Read installed software from the Uninstall registry keys.
- The script runs as SYSTEM: `HKCU`, `$env:USERPROFILE` and `$env:TEMP` are the SYSTEM profile, not the
  logged-on user's.

### Header
- Comment-based help: `.SYNOPSIS`, `.DESCRIPTION`, one `.PARAMETER` per parameter, `.EXAMPLE`, `.NOTES`, `.LINK`.
- `.NOTES` carries `Name`, `GUID` (same as the manifest), `Version` (semver), `Author`, `License`,
  `Platforms`, `Context`, `Exit codes` and `Changelog`.

### Parameters
- Use a `param()` block with named parameters and **safe defaults**.
- Arguments are stored in run history: **secrets only through environment variables** (manifest `env`),
  never as arguments.
- Agent values can be injected by the console with `{{agent.hostname}}`-style placeholders in `args`/`env`.

### Output
- Plain English, **ASCII only** (no accents, no emoji): Windows PowerShell 5.1 reads BOM-less files as ANSI.
- One fact per line, prefixed with `OK:`, `WARN:`, `FAIL:` or `INFO:`. First line = the verdict.
- Keep output **under 4 KB**: results are stored per agent and fleets have 10-15k agents.

### Exit codes
| Code | Meaning | Use in a script check |
|-----:|---------|-----------------------|
| 0 | OK | passing |
| 1 | FAIL / condition not met / error | failing |
| 2 | WARN | configure 2 as *warning* return code |
| 3 | NOT APPLICABLE (feature absent, unsupported edition) | configure 3 as *info* return code |

### Safety
- No customer data, hostnames, IPs, e-mails, tenant ids, keys or passwords in the repository.
- No downloading or executing remote code: no `Invoke-Expression`/`iex`, no `DownloadString`,
  no `Install-Module`/`Install-Package` at runtime, no `Invoke-WebRequest` of scripts.
- No telemetry: a script only talks to the network when testing the network is its purpose.
- **Never print secrets** (BitLocker recovery passwords, Wi-Fi keys, tokens).
- Scripts that delete or reset something take `-DryRun` and **default to dry run**.
- Never reboot unless `-AllowReboot` is passed.
- Idempotent: running twice must be harmless.
- `$ErrorActionPreference = 'Stop'` plus `try/catch`; always end with an explicit exit code, written as
  `$host.SetShouldExit($code); exit $code`. SONAR runs scripts without `-File`, and in that mode a plain
  `exit 2` reaches the console as `1`.

## Adding a script
1. Copy the template to `scripts/<category>/<Verb-Noun>.ps1`.
2. Generate a new GUID (`[guid]::NewGuid()`), put it in the header and in the manifest.
   **Never change or reuse a GUID**: it is how SONAR knows the script across versions.
3. Add the entry to [`sonar_scripts.json`](sonar_scripts.json).
4. Run `powershell -File tools/validate.ps1` (Windows PowerShell 5.1) and fix every finding.
5. Open a pull request. One review and a green CI run are required; releases are tags (`vX.Y.Z`).

## Manifest entry
```json
{
  "guid": "3f1c...",
  "filename": "inventory/Get-HardwareSummary.ps1",
  "name": "Inventory - Hardware summary",
  "description": "CPU, memory, disks, serial number, BIOS and TPM in a short report.",
  "shell": "powershell",
  "category": "Inventory",
  "args": [],
  "env": [],
  "syntax": "[-Threshold <int>]",
  "default_timeout": 90,
  "supported_platforms": ["windows"],
  "run_as_user": false
}
```
`filename` is relative to `scripts/`. `shell` is `powershell`, `cmd`, `python`, `shell` (bash) or `nushell`/`deno` where supported.

## Removing a script
Remove the manifest entry and the file. SONAR keeps a copy for every customer that still uses it
(check, task or alert action) as a customer-owned script; unused copies are removed.
