# Riposte 🗡️
**A portable PowerShell-based SOC triage and threat hunting toolkit.**

*Riposte (French: counterattack) — built for rapid response directly on the endpoint.*

*Made with Gemini + Claude*

---

## Overview
Riposte is a self-contained PowerShell script built for SOC analysts who need to hunt, triage, and remediate threats directly on an endpoint. Designed to run from a SentinelOne Remote Shell, ConnectWise ScreenConnect Backstage, WinRM, or any PowerShell-capable shell — no installations, no external tools, no hosting required.

---

## Capabilities

### Threat Hunting
- **Persistence Hunt** — Registry run keys, scheduled tasks, startup folders, and services
- **Global Keyword Hunt** — Cross-system search across registry, tasks, services, file system, running processes, and event logs with progress indicators
- **RMM Software Hunt** — Detects 25+ known remote monitoring and management tools (AnyDesk, ScreenConnect, TeamViewer, etc.) with install dates across processes, services, registry, and disk

### Execution & Process Analysis
- **PowerShell Execution History** — Event log (ID 4104) script block hunting with timeframe filter, SID-to-username resolution, and system account filtering
- **Broad Event Log Search** — Keyword-driven search across Security, System, Application, RDP, TaskScheduler, PowerShell, and Sysmon logs with structured per-event field display (IPs, accounts, command lines, file paths)

### ClickFix / Drive-By Triage
- **Recently Written Files Hunt** — Scans user profiles, AppData, temp paths, and known drop locations for recently created or modified files within a user-defined timeframe
- **RunMRU Execution Hunt** — Run dialog history across all user profiles including Azure AD accounts and offline hive mounting for logged-off users

### Forensics
- **DFIR System Info** — OS baseline, network config, local admins, and AV posture
- **Browser Forensics** — Extension auditing (name, version, source, permissions, install date, extension ID) and notification permission scanning with removal capability across Chrome, Edge, Brave, and Firefox

### Remediation
- Numbered result selection for targeted removal of registry keys, scheduled tasks, services, files, and processes
- Lock-aware file deletion — detects processes and services holding a locked file, prompts to stop them, and retries deletion automatically
- Exit and self-delete option (`D`) — removes the script file and optionally the containing folder if named `Riposte`

---

## Usage

**Pull from GitHub onto a device (recommended):**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JOkeyWalker/Riposte/refs/heads/main/Riposte.ps1" -OutFile "Riposte.ps1"
powershell -ExecutionPolicy Bypass -File "Riposte.ps1"
```

**Run a local copy:**
```powershell
powershell -ExecutionPolicy Bypass -File "C:\Path\To\Riposte.ps1"
```

Requires local administrator privileges.
