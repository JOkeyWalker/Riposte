# Riposte 🗡️
**A portable PowerShell-based SOC triage and threat hunting toolkit designed for remote shell environments.**

*Riposte (French: counterattack)*

---

## Overview
Riposte is a self-contained PowerShell script built for SOC analysts who need to hunt, triage, and remediate threats directly from remote shells such as SentinelOne Remote Shell, ConnectWise ScreenConnect Backstage, or WinRM — no agents, no installations, no hosting required. Copy, paste, and go.

---

## Capabilities

- **Persistence Hunt** — Registry run keys, scheduled tasks, startup folders, and services
- **Global Keyword Hunt** — Cross-system search across registry, tasks, services, file system, running processes, and event logs
- **SentinelOne Threat Detail Hunt** — Paste an S1 alerts "threat details" directly and automatically extract IOCs (filename, SHA1/SHA256, publisher, signer, originating process) for a full endpoint hunt
- **Stealth Persistence Hunt** — WMI event subscriptions and BITS job detection
- **RMM Software Hunt** — Detects 25+ known remote monitoring tools (AnyDesk, ScreenConnect, TeamViewer, etc.) with install dates across processes, services, registry, and disk
- **PowerShell Execution History** — Event log (ID 4104) script block hunting with timeframe filter and user resolution
- **Process Triage** — Unsigned processes, LOLBins, and execution from suspicious paths
- **ClickFix / Drive-by Triage** — Recently written files and RunMRU execution history
- **DFIR System Info** — OS baseline, network config, local admins, and AV posture

---

## Designed For
- Headless remote shell environments (no GUI, no interactive prompts beyond Read-Host)
- SentinelOne Remote Shell· ConnectWise ScreenConnect Backstage · WinRM
- Rapid triage without deploying additional tooling to the endpoint

---

## Usage
Paste directly into your remote shell or if running local copy on device:
```powershell
powershell -ExecutionPolicy Bypass -File "C:\Path\To\File\Riposte.ps1"
```
Requires local administrator privileges.
