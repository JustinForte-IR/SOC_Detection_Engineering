# Threat Hunting Report — Unauthorized RDP Access and Windows Service Persistence

**Project:** SOC Detection Engineering & Threat Hunting  
**Case ID:** HUNT-001  
**Case type:** Guided, simulated investigation (Phase 5 capstone)  
**Status:** Completed as an educational case study; no live SIEM validation  
**Environment:** Fictional Windows Server `SRV-02`  
**Analyst objective:** Assess whether the supplied events support unauthorized access, malicious execution, service-based persistence, and potential follow-on activity.

> **Evidence provenance:** Every event and EDR finding described in this case was provided as part of a **hypothetical training scenario**. This document is **not** a record of a real organizational breach, a live Splunk hunt, or independent forensic validation.

## 1. Executive summary

A simulated Windows host showed an Administrator RDP logon followed by PowerShell activity, a service installation, and a service start. The first set of logs supported **high suspicion**, but not confirmation of compromise. Additional *simulated* EDR telemetry and owner verification later established unauthorized access, malicious executable execution as SYSTEM, and a binary hash match to a confirmed malware sample. The case was therefore classified as a **confirmed compromise within the scenario**.

An outbound connection from the malicious executable was observed in the scenario. Its destination and purpose remained insufficiently established to claim confirmed command-and-control (C2) or exfiltration.

## 2. Hunt hypothesis and questions

**Hypothesis:** An adversary may use remote administrative access to execute commands and establish persistence through a newly installed Windows service.

Investigative questions:

1. Was the remote logon successful, and was it approved?
2. Can the authenticated session be linked to process execution?
3. Was a new service installed? Did it start, and did its executable run?
4. Is the service executable malicious or unauthorized?
5. Did the activity affect other endpoints or accounts?
6. Does observed outbound traffic indicate C2, exfiltration, or another purpose?

## 3. Telemetry and its evidentiary meaning

| Source | Event / observation | What it can establish | What it does **not** establish alone |
|---|---|---|---|
| Windows Security | 4624, Logon Type 10 | A successful RemoteInteractive logon event | That the login was attacker-controlled |
| Windows Security | 4688 | A process was created, subject to logging coverage | That the process performed every action contained in its command line |
| PowerShell Operational | 4104 | Script-block content was logged | That every command in the block completed successfully |
| Windows System | 7045 | A service was installed | That the service started or that the executable ran |
| Windows System | 7036 | A service entered a reported state | That it remains running now |
| EDR (simulated follow-up) | Parent/child process lineage | Supporting evidence for execution and process relationships | Definitive attribution of the human operator |
| File hash and malware intelligence (simulated) | SHA-256 match to known malware | Strong evidence of a malicious binary, assuming provenance is trustworthy | The full extent of its behavior or impact |
| Network telemetry (simulated) | Outbound connection | A network connection occurred | C2, exfiltration, or payload transfer without further analysis |

## 4. Simulated evidence timeline

All timestamps are **case-local illustrative times**, not recovered log exports.

| Time | Source | Observation | Assessment at this stage |
|---|---|---|---|
| 09:00:00 | 4624 | Administrator RDP logon from `10.10.20.45`, Logon ID `0xABC` | Remote administrative access observed; authorization initially unknown |
| 09:01:10 | 4688 | `powershell.exe -File C:\Scripts\deploy.ps1`, Logon ID `0xABC` | PowerShell created in associated logon context |
| 09:01:12 | 4104 | Script block contains `New-Service -Name WindowsHelper -BinaryPathName C:\Users\Public\helper.exe` | Service-creation code was logged; successful execution not proven by 4104 alone |
| 09:01:20 | 7045 | `WindowsHelper` service installed, configured for LocalSystem | Service installation established |
| 09:01:25 | 7036 | `WindowsHelper` entered Running state | Service start-state transition observed |
| Subsequent | EDR (simulated) | PowerShell PID `4820` launched `sc.exe` to create `WindowsHelper` | Service-creation process lineage corroborated |
| Subsequent | EDR (simulated) | `services.exe` launched `C:\Users\Public\helper.exe` as SYSTEM | Executable execution as SYSTEM corroborated |
| Subsequent | Malware intelligence (simulated) | Executable SHA-256 matched confirmed malware | Malicious binary identified within scenario |
| Subsequent | Owner/security validation (simulated) | RDP access and service installation both unauthorized | Unauthorized activity established |
| Subsequent | Network telemetry (simulated) | `helper.exe` connected to an unrecognized external IP | Purpose and content of communication unconfirmed |

**Analytical caution:** The logged `New-Service` script block and the EDR-observed `sc.exe` creation command may represent distinct attempts or related steps. The scenario does not provide sufficient detail to claim precisely how many creation attempts occurred.

## 5. Assessment progression

### Stage A — Before EDR and authorization checks

**Assessment: Highly suspicious; compromise not yet confirmed.**

The logon, PowerShell command content, service installation, and Running transition occurred in a short time span. The service path under `C:\Users\Public\` warranted attention. However, chronology and naming similarities alone were insufficient to establish the service-installation mechanism, maliciousness, or authorization status.

### Stage B — After corroborating evidence

**Assessment: Confirmed compromise within this simulated case.**

The conclusion is supported by unauthorized remote access, EDR-confirmed service-creation process lineage, EDR-confirmed execution of `helper.exe` as SYSTEM, and a match to a confirmed malware sample.

**Not confirmed:** who operated the session, initial credential theft mechanism, network communication purpose, exfiltration, spread to other hosts, and whether the service remains running at the time of later review.

## 6. MITRE ATT&CK mapping

| Technique | ID | Supporting simulated evidence | Qualification |
|---|---|---|---|
| Valid Accounts | T1078 | Unauthorized use of Administrator account | Account usage established; how credentials were obtained remains unknown |
| PowerShell | T1059.001 | PowerShell process and recorded script block | Command execution context corroborated by EDR for related `sc.exe` activity |
| Windows Service | T1543.003 | Installed service and launched malicious service binary | Persistence mechanism established in scenario |
| Remote Desktop Protocol | T1021.001 | RDP activity | Relevant RDP behavior; do not infer lateral movement between hosts without evidence |

**Do not assert a C2 technique merely from an outbound connection.** Confirm the function of the connection with additional endpoint and network data.

## 7. Example hunt searches — not executed

These are **illustrative SPL1 search patterns**. Adapt index names, sourcetypes, normalized fields, and timestamp handling to your environment. They are *not* validated detections or captured outputs.

### A. Review RDP logons on a target host

```spl
index=windows (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security") EventCode=4624
| eval logon_type=tonumber(coalesce(Logon_Type,LogonType))
| where logon_type=10
| eval account=coalesce(TargetUserName,user), source_ip=coalesce(IpAddress,Source_Network_Address), destination=coalesce(ComputerName,host)
| search destination="SRV-02"
| table _time destination account source_ip Logon_ID
| sort 0 _time
```

### B. Review process creation near the activity

```spl
index=windows (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security") EventCode=4688
| eval destination=coalesce(ComputerName,host), process=coalesce(New_Process_Name,NewProcessName), cmd=coalesce(Process_Command_Line,CommandLine)
| search destination="SRV-02"
| table _time destination SubjectUserName SubjectLogonId NewProcessId CreatorProcessId process cmd
| sort 0 _time
```

### C. Review newly installed services

```spl
index=windows (sourcetype="WinEventLog:System" OR sourcetype="XmlWinEventLog:System") EventCode=7045
| eval destination=coalesce(ComputerName,host), svc=coalesce(Service_Name,ServiceName), image_path=coalesce(Service_File_Name,ImagePath)
| search destination="SRV-02"
| table _time destination svc image_path Service_Account
| sort 0 _time
```

### D. Look for similar service paths across endpoints

```spl
index=windows (sourcetype="WinEventLog:System" OR sourcetype="XmlWinEventLog:System") EventCode=7045
| eval image_path=coalesce(Service_File_Name,ImagePath), destination=coalesce(ComputerName,host)
| where isnotnull(image_path) AND match(image_path,"(?i)\\\\users\\\\public\\\\|\\\\appdata\\\\|\\\\temp\\\\")
| table _time destination Service_Name image_path Service_Account
| sort 0 -_time
```

> **Important:** Field extraction names vary among Windows Event Log integrations. Where a field is missing, inspect raw or XML EventData before assuming no activity occurred. These searches do not demonstrate a causal chain without stable identifiers, time validation, and corroborating EDR telemetry.

## 8. Investigation and response recommendations

1. **Escalate:** Notify the designated SOC/IR lead with evidence, confidence assessment, impacted host/account, and unknowns.
2. **Preserve:** Record event sources and collection times; collect EDR process lineage, Security/System/PowerShell logs, hashes, file metadata, and relevant network telemetry, according to authorization and evidence procedures.
3. **Contain promptly under authority:** Coordinate risk-based host isolation, credential action, or network restrictions. Balance service criticality, safety, and evidence needs; do not delay urgent containment merely to finish collections.
4. **Scope:** Search for related file hashes, service names/paths, accounts, remote access origins, and network indicators across other hosts.
5. **Eradicate/recover:** Follow the incident commander's approved remediation and recovery plan; validate trusted state and monitor for recurrence.
6. **Improve detection:** Convert validated behaviors into layered rules and test false-positive/false-negative performance using representative benign and malicious samples.

## 9. Detection engineering lessons

- Retain **exact indicator** detections for known threats, but add **behavioral** detections to cover renamed services and executables.
- Validate field extraction, event availability, log retention, search time boundaries, thresholds, analyst context, and performance.
- Separate true positives, false positives, false negatives, and true negatives using labeled test cases.
- Treat a service-install event, a service state transition, and EDR-confirmed executable launch as distinct evidence types.
- Distinguish **observed network communication** from confirmed C2 or exfiltration.

## 10. Key limitations and future work

- The dataset, EDR confirmations, owner verification, and malware intelligence here are **fictional exercise evidence**.
- No corresponding production logs, EDR exports, packet captures, or malware sample are distributed.
- The example SPL searches have not been run against a live Splunk deployment.
- Future lab work should include representative synthetic telemetry, reproducible test cases, field normalization checks, and documented query results.

## 11. Ready summary

> "In a simulated hunt, I investigated unauthorized RDP access followed by PowerShell activity and Windows service installation. I initially rated the case as highly suspicious because event chronology alone didn't prove compromise. Follow-up simulated EDR, authorization, and malware-hash evidence supported a confirmed compromise. I mapped the supported behaviors to ATT&CK and kept outbound traffic classified as suspicious rather than automatically calling it C2. I documented containment, evidence collection, scope, and detection-validation priorities."

---

**Ethics and accuracy note:** This is a guided educational exercise. It does not represent employment experience, a real customer incident, or live-tested Splunk detections.
