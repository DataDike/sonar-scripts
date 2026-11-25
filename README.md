# SONAR Script Library

Public, open-source library of maintenance and security scripts maintained by **DataDike** for
[SONAR](https://datadike.com). Every SONAR console ships with these scripts under
**Scripts > SONAR Library**, ready to run on demand, in automation tasks or as script checks.

The scripts are plain PowerShell and work on their own too: read them, run them, adapt them.

## What is inside

| Category | Examples |
|----------|----------|
| Inventory | hardware summary, installed software, Windows activation, uptime and pending reboot |
| Cleanup | temp files and update cache (dry run by default), free disk space check |
| Windows Update | update health, days since last install, component reset |
| BitLocker | volume status, recovery key present and backed up, TPM and Secure Boot |
| Defender | protection status, signature update and scan, recent detections |
| Network | connectivity diagnostics, network stack reset, listening ports |
| Security | local administrators, firewall profiles, SMBv1, RDP security |
| Services | service running (optional start) |

The full list, with arguments and defaults, is in [`sonar_scripts.json`](sonar_scripts.json).

## Conventions

- Windows PowerShell **5.1** compatible, run as **SYSTEM**.
- First output line is the verdict: `OK:`, `WARN:`, `FAIL:` or `INFO:`.
- Exit codes: `0` OK, `1` FAIL, `2` WARN, `3` not applicable. In a SONAR script check, set
  `2` as a warning return code and `3` as an informational return code.
- Anything that deletes or resets runs as a **dry run** unless you pass `-DryRun:$false`.
  Nothing reboots unless you pass `-AllowReboot`.
- No secrets are ever printed (for example, BitLocker recovery passwords).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full writing standard.

## How SONAR uses this repository

SONAR servers pin a **release tag** (for example `v1.0.0`), never the `main` branch. A new tag
reaches customers only when DataDike updates the platform. When a script leaves the library,
every customer that still uses it (in a check, task or alert action) keeps a copy as their own
script, so nothing stops working.

## Repository layout

```
sonar_scripts.json        manifest read by SONAR
scripts/<category>/       one file per script
templates/                starting point for a new script
tools/validate.ps1        validation run by CI on every pull request
```

## Validate locally

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/validate.ps1
```

## Security

Found a security issue in a script? Please do not open a public issue: report it privately via
GitHub Security Advisories ("Report a vulnerability" on the Security tab).

## License

[MIT](LICENSE) (c) DataDike
