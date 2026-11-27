# Changelog

## v1.1.1 (2026-11-27)
- Security - Domain and Entra join: internal helper renamed to pass PSScriptAnalyzer (no behaviour change).

## v1.1.0 (2026-11-27)
- 22 new scripts (45 in total) and 3 new categories:
  - Hardware: disk health, battery health.
  - Maintenance: system file repair, clear print queue, time synchronization.
  - Troubleshooting: crashes and unexpected shutdowns, event log errors.
  - Inventory: monitors, printers, Microsoft Office, startup programs, user profiles, logged-on users.
  - Security: hardening baseline, failed logons, local accounts, expiring certificates,
    suspicious scheduled tasks, browser extensions, domain and Entra join.
  - Cleanup: browser cache. Network: Wi-Fi status.
- Fix: exit codes 2 (WARN) and 3 (NOT APPLICABLE) now reach SONAR. Scripts run without `-File`,
  where a plain `exit 2` returned 1; every script now uses `$host.SetShouldExit(N); exit N`,
  and the validator enforces it.

## v1.0.0 (2026-11-24)
First release: 23 scripts in 8 categories (Inventory, Cleanup, Windows Update, BitLocker,
Defender, Network, Security, Services), writing standard, template and CI validation.
