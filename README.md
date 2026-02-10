# Nova Ransomware IR — Incident Response Portfolio

A defensive, portfolio-grade **Incident Response Lead** repository documenting ransomware investigation procedures.

> ⚠️ **Disclaimer:** This project contains **no malware**, **no real victim data**, and is intended for **defensive education** and DFIR practice only.

---

## 📋 Overview

This repository provides:
- **Log sources** required to investigate modern ransomware intrusions end-to-end
- **Non-overlapping** correlation logic for Microsoft Sentinel (KQL) and Splunk (SPL)
- Investigation notebooks that turn logs into scope, timeline, and containment actions
- **SOC runbooks** with RACI, compliance mappings, and workflow diagrams

---

## 📂 Repository Layout

```
Nova_Ransomware/
├── notebooks/                  # Jupyter notebooks (IR workflow + correlations)
├── docs/                       # MITRE mapping + mock executive summary
├── detections/                 # Sigma + YARA-L examples (defensive only)
├── screenshots/                # Timeline diagrams
├── nova-ransomware-runbook/    # SOC runbook pack (runbooks, RACI, compliance mapping)
└── data/                       # Intentionally empty; guidance only (no logs committed)
```

---

## 🔧 Environment & Technology Stack

### Endpoint Telemetry
- **Microsoft Defender for Endpoint (MDE)**
  - Integrated into Sentinel
  - Tables available for querying
  
- **Sysmon**
  - Deployed on Windows endpoints and servers

### Network/Edge Telemetry
- **Cloudflare**
  - Gateway
  - DNS
  - Access
  - WAF
  - Audit logs

### SIEM Platforms
- **Microsoft Sentinel** (KQL queries)
- **Splunk** (SPL queries)

---

## 📊 Required Log Types

### 1️⃣ Endpoint Execution & Impact

**Purpose:** Identify payload execution, pre-encryption prep, and encryption impact

#### Microsoft Defender for Endpoint (MDE)
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceLogonEvents`

#### Sysmon Events
- **EventID 1** — Process creation
- **EventID 11** — File create
- **EventID 3** — Network connection
- **EventID 22** — DNS query
- **EventID 13** — Registry modification

---

### 2️⃣ Authentication & Privilege Changes

**Purpose:** Detect credential abuse and privilege escalation

#### Windows Security Events
- **4624 / 4625** — Successful/Failed logons
- **4672** — Admin privileges assigned
- **4720 / 4728 / 4732** — Account/Group changes
- **1102** — Security log cleared

#### MDE Events
- `DeviceLogonEvents` — Endpoint view of logons

---

### 3️⃣ Lateral Movement Execution Channels

**Purpose:** Detect remote execution and admin tooling misuse

#### Windows System Events
- **7045** — Service installation

#### Windows Security Events
- **4698** — Scheduled task creation

#### Process Telemetry (MDE/Sysmon)
Monitor for:
- PsExec
- WMI execution
- schtasks
- sc.exe
- net.exe usage

---

### 4️⃣ Network Egress & Possible Exfiltration

**Purpose:** Detect pre-encryption staging/exfil and block paths quickly

#### Cloudflare Logs
- Gateway HTTP/DNS logs
- Access logs
- WAF logs
- Audit logs

#### Sentinel Integration
Data arrives in:
- `CommonSecurityLog` (CEF/Syslog format)
- Cloudflare custom table (connector-dependent)

---

### 5️⃣ Backup / Recovery Tampering

**Purpose:** Identify attempts to prevent recovery

#### Monitor for Commands
- `vssadmin`
- `wmic`
- `wbadmin`
- `bcdedit`
- `wevtutil`

#### Additional Sources
- Backup platform logs (if available)
- Windows eventing for backup failures/deletions

---

## 🔍 Correlation Logic

Each query serves a **distinct IR decision point** with non-overlapping logic.

---

### A) Impact Confirmation: File Modification Spike

**Decision Supported:** *"Is encryption occurring now, and where?"*

#### Microsoft Sentinel (KQL)
```kusto
DeviceFileEvents
| where Timestamp > ago(6h)
| summarize FileOps=count(), DistinctFiles=dcount(FileName) by DeviceName, bin(Timestamp, 5m)
| where FileOps > 500
| order by FileOps desc
```

#### Splunk (SPL) — Sysmon EventID 11
```spl
index=endpoint earliest=-6h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| bin _time span=5m
| stats count as file_ops dc(TargetFilename) as distinct_files by host _time
| where file_ops > 500
| sort - file_ops
```

---

### B) Pre-Impact Recovery Inhibition

**Decision Supported:** *"Are they attempting to destroy recovery paths?"*

#### Microsoft Sentinel (KQL)
```kusto
let bad = dynamic(["vssadmin delete shadows","wmic shadowcopy delete","wbadmin delete","bcdedit","wevtutil cl"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (bad)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

#### Splunk (SPL)
```spl
index=endpoint earliest=-24h
(CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*bcdedit*" OR CommandLine="*wevtutil* cl*")
| table _time host user Image CommandLine
| sort - _time
```

---

### C) Remote Execution Channel Detection

**Decision Supported:** *"Are they spreading via remote services/tasks?"*

#### Microsoft Sentinel (KQL) — Service Installation
```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 7045
| project TimeGenerated, Computer, Account, ServiceName, ImagePath
| order by TimeGenerated desc
```

#### Splunk (SPL) — Scheduled Task Creation
```spl
index=wineventlog earliest=-24h sourcetype="WinEventLog:Security" EventCode=4698
| table _time host user TaskName Command
| sort - _time
```

---

### D) Credential Abuse Indicator

**Decision Supported:** *"Is one source rapidly authenticating across the estate?"*

#### Microsoft Sentinel (KQL)
```kusto
SecurityEvent
| where TimeGenerated > ago(6h)
| where EventID == 4624
| summarize Logons=count() by IpAddress, Account, bin(TimeGenerated, 10m)
| order by Logons desc
```

#### Splunk (SPL)
```spl
index=wineventlog earliest=-6h sourcetype="WinEventLog:Security" EventCode=4624
| bin _time span=10m
| stats count as logons by _time IpAddress AccountName
| sort - logons
```

---

### E) Privilege Escalation: Group Membership Changes

**Decision Supported:** *"Did they escalate by modifying group membership?"*

#### Microsoft Sentinel (KQL)
```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728,4732)
| project TimeGenerated, Computer, SubjectAccount=Account, AddedMember=TargetAccount, Group=TargetUserName
| order by TimeGenerated desc
```

#### Splunk (SPL)
```spl
index=wineventlog earliest=-7d sourcetype="WinEventLog:Security" (EventCode=4728 OR EventCode=4732)
| table _time host SubjectUserName TargetUserName MemberName
| sort - _time
```

---

### F) Network/Exfiltration Suspicion

**Decision Supported:** *"Is there likely data staging/exfil via HTTP/S?"*

#### Microsoft Sentinel (KQL)
*Note: Field names vary by connector*

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor has "Cloudflare" or DeviceProduct has "Cloudflare"
| where Message has_any ("upload","PUT","POST","multipart") or RequestURL has_any ("upload","transfer","share")
| project TimeGenerated, SourceIP, RequestURL, DeviceAction, Message
| order by TimeGenerated desc
```

#### Splunk (SPL)
*Note: Adjust index/sourcetype and field names as needed*

```spl
index=cloudflare earliest=-24h
(http_method=POST OR http_method=PUT OR url="*upload*" OR url="*transfer*" OR url="*share*")
| stats count as hits sum(bytes_out) as egress_bytes by src_ip user url
| sort - egress_bytes
```

---

## 🔗 Joining Cloudflare ↔ Endpoint Data

To correlate Cloudflare `src_ip` to a specific device:

### Option 1: MDE DeviceNetworkEvents
Use `DeviceNetworkEvents` to map **DeviceName → LocalIP**

### Option 2: DHCP/CMDB Lookups
Best for dynamic IP environments

---

## 📚 SOC Runbook Pack

The **nova-ransomware-runbook/** directory contains operational materials for SOC teams:

- **One-page SOC runbook** — Step-by-step response procedures for M365 and Google Workspace
- **RACI matrix** — Role assignment and accountability framework
- **Workflow diagram** — Visual incident response flow (Mermaid format)
- **Compliance mappings** — ISO 27001, NIST CSF & 800-53, SOC 2 control mappings
- **Vendor security addendum** — Contract-ready clause for vendor agreements

See [nova-ransomware-runbook/README.md](nova-ransomware-runbook/README.md) for details.

---

## ⚖️ Safety & Ethics

### ⛔ Do NOT:
- Upload production logs, PII, or customer data
- Store or distribute ransomware binaries
- Use for offensive purposes

### ✅ DO:
- Use this repo for defensive detection engineering
- Practice IR readiness and DFIR skills
- Contribute improvements and share knowledge

---

## 👤 Author

**Autobot786**  
Incident Response / DFIR

---

## 📜 License

This project is for educational and defensive purposes only.
