# 🔴 Incident Response Report  
## Akira Ransomware Attack  
**Client:** Ashford Sterling Recruitment  
**Classification:** TLP:RED – Confidential  
**Date:** Jan 27–28, 2026  
**Case ID:** INC-2026-AKIRA-ASR  

---

## 🧾 Executive Summary

Ashford Sterling Recruitment experienced a ransomware attack conducted by the Akira ransomware group, resulting in system compromise, data exfiltration, and file encryption.

The attacker regained access through a previously established remote access tool (AnyDesk) and executed a full attack chain within approximately 80 minutes. This included disabling security controls, harvesting credentials, moving laterally, exfiltrating data, and deploying ransomware.

The presence of staged data (`exfil_data.zip`) indicates a double-extortion scenario, where stolen data may be used for additional leverage.

### 🔴 Business Impact
- Critical systems encrypted (AS-PC2, AS-SRV)
- Potential data breach exposure
- Loss of operational availability
- Risk of regulatory and reputational damage

---

## 🕒 Incident Overview

### Attack Flow

1. Initial access via AnyDesk (pre-staged)
2. Windows Defender disabled
3. Credential harvesting (LSASS)
4. Internal reconnaissance and scanning
5. Lateral movement to AS-SRV
6. Data staging and exfiltration
7. Ransomware deployment
8. Backup deletion and encryption

## Attack Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| ~21:00 | AS-PC2 | AnyDesk executed from `C:\Users\Public` by `david.mitchell` |
| **21:03:42** | AS-PC2 | Registry modified — `DisableAntiSpyware` set via `kill.bat` |
| ~21:05 | AS-PC2 | LSASS targeted via `tasklist \| findstr lsass` |
| ~21:10 | AS-PC2 | Named pipe `\Device\NamedPipe\lsass` accessed |
| ~21:15 | AS-PC2 | `wsync.exe` (C2 beacon v1) deployed to `C:\ProgramData\` |
| ~21:20 | AS-PC2 | `scan.exe` deployed; enumeration of `10.1.0.154`, `10.1.0.183` |
| ~21:30 | AS-PC2 | `bitsadmin.exe` attempted download from `sync.cloud-endpoint.net` |
| ~21:35 | AS-PC2 | `Invoke-WebRequest` fallback; `wsync.exe` v2 beacon deployed |
| ~21:50 | AS-SRV | Lateral movement via `as.srv.administrator` |
| ~22:00 | AS-SRV | `st.exe` deployed; `exfil_data.zip` archive created |
| ~22:05 | AS-SRV | `updater.exe` (ransomware) staged by `powershell.exe` |
| ~22:10 | AS-SRV | `wmic shadowcopy delete` — VSS copies wiped |
| **22:18:33** | AS-SRV | Ransom note dropped by `updater.exe` — encryption commenced |
| ~22:20 | AS-SRV | `Clean.bat` executed — ransomware binary self-deleted |

---

## 🔍 Key Findings

### Unauthorized Remote Access
- AnyDesk executed from `C:\Users\Public`
- No monitoring or restriction policies in place

### Defense Evasion
- Antivirus disabled via registry modification (`kill.bat`)
- No alerting or blocking of security control tampering

### Credential Compromise
- LSASS targeted for credential extraction
- Privileged account used for lateral movement

### Data Exfiltration
- Archive created: `exfil_data.zip`
- Indicates high likelihood of data theft

### Ransomware Execution
- Malware deployed as `updater.exe`
- Shadow copies deleted prior to encryption

---

## 🚨 Root Cause Analysis

The attack was enabled by the following control failures:

- Unrestricted remote access tools (AnyDesk)
- Lack of endpoint protection hardening
- No credential protection mechanisms (e.g., LSASS protection)
- Excessive administrative privileges
- No application control policies
- Insufficient monitoring and alerting

---

## ⚠️ Missed Detection Opportunities

The following events should have triggered alerts:

- Execution of AnyDesk from non-standard path  
- Registry changes disabling antivirus  
- LSASS access attempts  
- Creation of compressed archive files  
- Shadow copy deletion commands  

---

## 🧪 Selected Detection Queries (KQL)

### 🔎 Detect Suspicious Remote Access Tool Execution

```kql
DeviceProcessEvents
| where FileName == "AnyDesk.exe"
| where FolderPath !startswith "C:\\Program Files"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| order by TimeGenerated desc
```
### 🔎 Detect Windows Defender Tampering
```kql
DeviceRegistryEvents
| where RegistryValueName == "DisableAntiSpyware"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData
| order by TimeGenerated desc
```
### 🔎 Detect LSASS Access Activity

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where PipeName contains "lsass"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, PipeName

```
### 🔎 Detect Shadow Copy Deletion
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete", "wmic shadowcopy delete")
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName
| order by TimeGenerated desc
```
### 🔎 Detect Suspicious Archive Creation (Exfiltration)
```kql
DeviceFileEvents
| where FileName endswith ".zip"
| where InitiatingProcessFileName !in~ ("explorer.exe")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessFileName
```
----

## 🛠️ Remediation & Mitigation
### 🔴 Immediate Actions

- Isolate and rebuild affected systems
- Reset all credentials (user and admin)
- Block identified malicious domains and IPs

---

### 🟠 Short-Term Improvements
#### Secure Remote Access
- Remove unauthorized tools (AnyDesk)
- Enforce Multi-Factor Authentication (MFA)
  
#### Credential Protection
- Enable Credential Guard
- Reduce administrative privileges
  
#### Endpoint Security
- Enable tamper protection
- Monitor security control changes

---

### 🟢 Long-Term Protection (SMB-Focused)

#### Application Control
Block execution from:
> `C:\Users\Public`

> `C:\ProgramData`

#### Ransomware Resilience 
- Implement offline / immutable backups
- Test recovery procedures regularly

#### Monitoring & Detection
- Deploy centralized logging (SIEM)
- Monitor outbound traffic anomalies

#### User Awareness
- Conduct security awareness training

-----

## 📌 Conclusion
This incident highlights how quickly ransomware attacks can escalate when foundational security controls are not in place.
The attacker leveraged common techniques, but the absence of layered defenses allowed rapid progression from access to full system compromise.
Implementing the recommended controls will significantly reduce the likelihood and impact of future ransomware incidents.

---

## 📎 Appendix (Summary of Key IOCs)

#### Domains
- sync.cloud-endpoint.net
- cdn.cloud-endpoint.net
  
#### IP Addresses

 `172.67.174.46`

 `104.21.30.237`
 
 `88.97.164.155`

#### Key Files

- kill.bat
- wsync.exe
- scan.exe
- st.exe
- updater.exe
- exfil_data.zip
---


| Field | Detail |
|---|---|
| **Case Reference** | INC-2026-AKIRA-ASR |
| **Classification** | TLP:RED — Not for distribution |
| **Date** | 2026-01-27 / 2026-01-28 |
| **Affected Hosts** | AS-PC2, AS-SRV |
| **Victim ID** | 813R-QWJM-XKIJ |
| **Threat Actor** | Akira Ransomware Group |
| **Encrypted Extension** | `.akira` |

---

Over an approximately **80-minute operational window** on 27–28 January 2026, the attacker:
- Disabled Windows Defender via registry modification (`kill.bat`)
- Harvested credentials by targeting LSASS
- Moved laterally to AS-SRV using `as.srv.administrator`
- Exfiltrated a compressed data archive (`exfil_data.zip`)
- Deployed Akira ransomware masqueraded as `updater.exe`
- Wiped Volume Shadow Copies before encryption
- Dropped the ransom note at **22:18:33 UTC**

---

## Appendix A — Indicators of Compromise (IOCs)

> 

### Domains

| Indicator | Context |
|---|---|
| `sync.cloud-endpoint.net` | Payload hosting / C2 |
| `cdn.cloud-endpoint.net` | Ransomware staging |
| `relay-0b975d23.net.anydesk.com` | AnyDesk relay (primary) |
| `relay-c6eb91af.net.anydesk.com` | AnyDesk relay (secondary) |
| `relay-b8f8a0be.net.anydesk.com` | AnyDesk relay (secondary) |

### IP Addresses

| Indicator | Context |
|---|---|
| `172.67.174.46` | C2 infrastructure (sync.cloud-endpoint.net) |
| `104.21.30.237` | C2 infrastructure (cdn.cloud-endpoint.net) |
| `88.97.164.155` | Attacker external IP (AnyDesk session) |

### File Hashes (SHA256)

| Hash | Filename | Context |
|---|---|---|
| `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` | kill.bat | Defense evasion script |
| `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` | wsync.exe | C2 beacon (original) |
| `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` | wsync.exe | C2 beacon (replacement) |
| `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` | scan.exe | Network scanner |
| `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` | st.exe | Data staging tool |
| `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` | updater.exe | Akira ransomware binary |

### Files & Artefacts

| Filename | Path | Context |
|---|---|---|
| `kill.bat` | C:\ProgramData\ | Defense evasion script |
| `wsync.exe` | C:\ProgramData\ | C2 beacon |
| `scan.exe` | C:\Users\david.mitchell\Downloads\ | Network scanner (Advanced IP Scanner) |
| `st.exe` | C:\ProgramData\ | Data staging / compression tool |
| `exfil_data.zip` | AS-SRV | Exfiltration archive |
| `updater.exe` | C:\ProgramData\ | Akira ransomware binary |
| `Clean.bat` | AS-SRV | Anti-forensics cleanup script |
| `akira_readme.txt` | Multiple directories on AS-SRV | Ransom note |

### Accounts

| Account | Context |
|---|---|
| `david.mitchell` | Compromised user on AS-PC2 |
| `as.srv.administrator` | Local admin used for lateral movement to AS-SRV |

### TOR

| Indicator | Context |
|---|---|
| `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | Akira negotiation portal |

---

## Appendix B — MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Observed Activity |
|---|---|---|---|
| Initial Access | T1133 | External Remote Services | AnyDesk pre-staged from prior compromise |
| Execution | T1059.001 | PowerShell | Invoke-WebRequest, powershell.exe staging ransomware |
| Persistence | T1543 | Create/Modify System Process | wsync.exe C2 beacon dropped in ProgramData |
| Defense Evasion | T1562.001 | Disable or Modify Tools | kill.bat + DisableAntiSpyware registry modification |
| Defense Evasion | T1036.005 | Match Legitimate Name/Location | updater.exe masquerading as Windows update process |
| Credential Access | T1003.001 | LSASS Memory | tasklist \| findstr lsass + named pipe lsass access |
| Discovery | T1046 | Network Service Scanning | scan.exe portable network enumeration |
| Discovery | T1135 | Network Share Discovery | net view against 10.1.0.154, 10.1.0.183 |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | as.srv.administrator lateral auth to AS-SRV |
| Command & Control | T1219 | Remote Access Software | AnyDesk via relay-0b975d23.net.anydesk.com |
| Command & Control | T1071.001 | Application Layer Protocol: Web | wsync.exe beacon over HTTP/HTTPS |
| Exfiltration | T1560.001 | Archive via Utility | st.exe creating exfil_data.zip |
| Impact | T1486 | Data Encrypted for Impact | updater.exe Akira ransomware deployment |
| Impact | T1490 | Inhibit System Recovery | wmic shadowcopy delete + vssadmin delete shadows |

---

## Recommendations

1. **Block all IOC domains and IPs** at the perimeter firewall and internal DNS resolver immediately — `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, `172.67.174.46`, `104.21.30.237`.
2. **Isolate and reimage AS-PC2 and AS-SRV.** Do not attempt in-place remediation given the depth of compromise and confirmed anti-forensics activity.
3. **Reset all credentials** associated with `david.mitchell` and `as.srv.administrator`. Treat all cached credentials on both hosts as fully compromised.
4. **Audit all privileged accounts** for unauthorised changes. Review the original Broker incident access vector to identify any additional harvested credentials not yet used.
5. **Implement Application Control** (WDAC or AppLocker) to prevent unsigned binary execution from `C:\Users\Public`, `C:\ProgramData\`, and other user-writable paths.
6. **Enable Microsoft Credential Guard** to prevent LSASS memory access via the named pipe interface exploited during this intrusion.
7. **Restrict BitsAdmin and PowerShell download capability** via Group Policy. Apply Constrained Language Mode for PowerShell where operationally feasible.
8. **Deploy an AnyDesk allowlist policy** restricting connections to approved relay domains and external IPs. If AnyDesk is not a business requirement, block its execution entirely.
9. **Protect VSS snapshots** using tamper-resistant backup solutions that cannot be deleted via `wmic` or `vssadmin` from compromised user or administrator context.
10. **Engage with the Akira negotiation portal only through qualified legal counsel.** Preserve victim ID `813R-QWJM-XKIJ` for all incident records and insurance correspondence.

---

*Report produced by Gaddis M. as part of the SancLogic Cyber Range — The Buyer (Advanced) threat hunt exercise.*
*Platform: Microsoft Defender for Endpoint + Microsoft Sentinel | Query Language: KQL*
