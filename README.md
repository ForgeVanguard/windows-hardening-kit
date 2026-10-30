# windows-hardening-kit

A reversible security baseline for standalone Windows 10/11 workstations and lab machines,
plus a weekly check script to confirm it stays applied.

| Script | Purpose |
|---|---|
| `scripts/Invoke-WindowsHardening.ps1` | Applies the baseline. Snapshots every value it touches to JSON first. Supports `-WhatIf`. |
| `scripts/Undo-WindowsHardening.ps1` | Restores exactly the previous values from that snapshot. |
| `scripts/Test-WindowsHardening.ps1` | Read-only weekly check. Exit code = number of issues. |
| `scripts/HardeningCommon.psm1` | Shared setting definitions (ASR rule list, registry values, services). |

## What the baseline does

| Section | Change |
|---|---|
| Defender | Real-time on, cloud protection (MAPS Advanced), safe sample submission, PUA blocking, 10 ASR rules (audit or block) |
| Network | SMBv1 server off, SMB signing required (client + server), LLMNR off |
| Credential | WDigest plaintext credentials off, UAC on with secure-desktop consent |
| Autorun | AutoRun/AutoPlay off for all drive types |
| Firewall | All profiles on, inbound default block, dropped-packet logging |
| Services | Remote Registry disabled |
| Spooler | Print Spooler disabled (skip with `-Skip Spooler` if you print) |
| Rdp | Inbound Remote Desktop off (skip with `-Skip Rdp` if you use it) |
| Privacy | Diagnostic data = Required; Edge optional diagnostics off |
| Lockout | 5 failed attempts -> 15-minute lockout |

Optional: `-ManagementPort 3000 -ManagementSubnet 192.0.2.0/24` scopes a self-hosted dashboard
port to a management subnet; `-DisableBuiltinAdministrator` disables the built-in Administrator
when another admin account exists. BitLocker and admin group membership are reported, not changed.

### ASR rules

| GUID | Rule |
|---|---|
| 56a863a9-875e-4185-98a7-b882c64b5ce5 | Block abuse of exploited vulnerable signed drivers |
| 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c | Block Adobe Reader from creating child processes |
| d4f940ab-401b-4efc-aadc-ad5f3c50688a | Block all Office applications from creating child processes |
| 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Block credential stealing from LSASS |
| be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block executable content from email client and webmail |
| 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Block execution of potentially obfuscated scripts |
| d3e037e1-3eb8-44c8-a917-57927947596d | Block JavaScript or VBScript from launching downloaded executable content |
| 3b576869-a4ec-4529-8536-b80a7769e899 | Block Office applications from creating executable content |
| 26190899-1602-49e8-8b27-eb1d0a1ce869 | Block Office communication application from creating child processes |
| e6db77e5-3df2-4cf1-b95a-636979351e5b | Block persistence through WMI event subscription |

## Usage

```powershell
# Preview everything
.\scripts\Invoke-WindowsHardening.ps1 -WhatIf

# First pass: ASR in audit mode, keep printing
.\scripts\Invoke-WindowsHardening.ps1 -AsrMode AuditMode -Skip Spooler

# After reviewing Defender events (Microsoft-Windows-Windows Defender/Operational, ID 1122), enforce
.\scripts\Invoke-WindowsHardening.ps1 -AsrMode Enabled -Skip Spooler

# Weekly check from your daily account
.\scripts\Test-WindowsHardening.ps1 -ExpectedAdmin <USERNAME>

# Roll back the most recent run
.\scripts\Undo-WindowsHardening.ps1 -WhatIf
.\scripts\Undo-WindowsHardening.ps1
```

Snapshots live in `%ProgramData%\WindowsHardeningKit\State`. Reboot after applying or undoing.

## Design notes

- **Rollback is targeted.** Undo only restores values that the snapshot recorded, so it never
  turns on something (SMBv1, a firewall profile) that was off before hardening.
- **ASR rules are appended** with `Add-MpPreference`; calling `Set-MpPreference` once per rule
  replaces the list each time and leaves only the last rule configured.
- **Managed devices:** on Intune/GPO-managed machines, push these settings from the management
  platform instead; local changes can be overwritten.
- `net accounts` output is parsed for the lockout snapshot, which assumes an English display language.

## Testing

All scripts parse cleanly and pass PSScriptAnalyzer (`PSScriptAnalyzerSettings.psd1`).
Windows-only: tested for syntax only. Run with `-WhatIf` first on any new machine.

## License

MIT - Steven Drew
