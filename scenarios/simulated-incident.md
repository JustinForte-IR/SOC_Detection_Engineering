# Simulated Incident Case Study: Unauthorized RDP and Malicious Windows Service

**Project:** SOC Detection Engineering & Threat Hunting  
**Case ID:** SIM-IR-005  
**Affected host:** `SRV-02` (fictional)  
**Case type:** Guided training simulation; **not** a real enterprise incident  
**Final case classification:** Confirmed compromise **within the simulation**

## 1. Executive summary

The scenario begins with an Administrator RDP session, followed by PowerShell activity and installation of a Windows service called `WindowsHelper`. Early Windows event data makes the sequence suspicious but does not, on its own, prove that the activity was unauthorized or malicious. A later simulated EDR and authorization evidence set establishes that the RDP session and service installation were unauthorized, connects service creation to the administrator's process activity, confirms the service-launched binary executed as SYSTEM, and matches the binary to a known malicious sample. This supports a **confirmed compromise in the scenario**.

The binary also makes an outbound connection to an unrecognized external IP. The connection's purpose is **unverified**; command-and-control and exfiltration are **not confirmed**.

## 2. Hypothesis and scope

**Hypothesis:** An adversary used an administrator account over RDP, executed commands, and established Windows service-based persistence.

**Investigation scope:** Remote authentication, PowerShell and child process behavior, Windows service configuration and execution, file reputation, authorization, and outbound communication.

**Evidence sources:** Hypothetical Windows Security, PowerShell Operational, System, and EDR records, together with hypothetical threat-intelligence and system-owner validation.

## 3. Evidence set 1 — Initial host telemetry

All timestamps below are **fictional scenario-local times on the same host**, not real forensic exports.

| Time | Source | Observation | Supported conclusion |
|---|---|---|---|
| 09:00:00 | Security 4624 | Administrator RemoteInteractive (Logon Type 10) from `10.10.20.45`; Logon ID `0xABC` | A recorded successful remote-interactive authentication; not proof of unauthorized access |
| 09:01:10 | Security 4688 | `powershell.exe -File C:\Scripts\deploy.ps1`, associated with Logon ID `0xABC` | PowerShell process creation associated with that logon; the event alone does not prove script effects |
| 09:01:12 | PowerShell 4104 | Script-block text includes `New-Service -Name WindowsHelper -BinaryPathName C:\Users\Public\helper.exe` | Command text was recorded; additional evidence is needed to establish successful service creation by this exact command |
| 09:01:20 | System 7045 | `WindowsHelper` installed, configured with a LocalSystem service account | Windows recorded service installation; does not establish service execution |
| 09:01:25 | System 7036 | `WindowsHelper` entered the Running state | The service reached Running at this time; not proof that it is still running |

**Initial judgment:** High-priority suspicious sequence, but **not yet a confirmed compromise**. Legitimate administrative deployment remains an alternative until authorization and executable behavior are checked.

## 4. Evidence set 2 — Subsequent simulated validation

1. EDR associates `powershell.exe` PID `4820` with the Administrator RDP session and confirms that it launched `sc.exe` with a command to create `WindowsHelper`.
2. EDR confirms `services.exe` launched `C:\Users\Public\helper.exe` as `NT AUTHORITY\SYSTEM`.
3. The full SHA-256 hash of `helper.exe` matches an organization's confirmed malicious sample.
4. The security team and system owner confirm that the RDP access and service installation were **unauthorized**.
5. EDR records an outbound connection by `helper.exe` to an external IP not recognized as an approved destination. Protocol, data contents, and purpose are not yet established.

**Mechanism note:** The 4104 record contains `New-Service`, while EDR confirms a child `sc.exe` service-creation command. Both are relevant evidence, but the scenario does not establish whether the script-block command succeeded or whether it and `sc.exe` were separate attempts. Do not invent a definitive sequence beyond the given records.

## 5. Final assessment

**Confirmed within the simulated scenario:**

- Administrator RDP access and service installation were unauthorized.
- PowerShell launched the service-creation utility according to EDR.
- A Windows service launched a malware-matching binary as SYSTEM.
- The host was compromised in the scenario.

**Not yet confirmed:**

- The true identity of the remote actor or how the credentials were obtained.
- Lateral movement to other hosts.
- Whether the outbound connection was command-and-control.
- Data exfiltration or its absence.
- Whether the service or connection remains active at the time of response.

## 6. MITRE ATT&CK mapping

| Technique | Basis | Caveat |
|---|---|---|
| **T1078 — Valid Accounts** | Unauthorized use of Administrator credentials | Credential theft method is unknown |
| **T1059.001 — PowerShell** | Recorded PowerShell process and script activity | Do not equate all logged command text with successful effects |
| **T1543.003 — Windows Service** | Installed service linked to malware execution | Installation and execution are separately evidenced |
| **T1021.001 — Remote Desktop Protocol** | RemoteInteractive/RDP access | Its role in lateral movement depends on the broader access context |

**No confirmed C2 technique is mapped:** An unexplained outbound connection alone is insufficient.

## 7. SOC analyst response priorities

1. **Escalate:** Report a confirmed compromise through the authorized incident-response path, including evidence confidence and unknowns.
2. **Preserve:** Coordinate event, EDR, process, network, binary, and volatile evidence collection as appropriate; record timestamps, provenance, and custody.
3. **Contain:** Request prompt risk-based isolation or scoped restrictions through the approved response authority. Avoid unnecessary delays for evidence collection where active harm is likely.
4. **Scope:** Hunt other hosts for the malicious SHA-256, service name/path, related accounts, RDP source, and corroborated network indicators.
5. **Eradicate and recover:** Through authorized teams, eliminate persistence, address access paths and credentials, restore trusted systems, and validate health.
6. **Monitor and improve:** Validate containment and recovery, refine detections, and document lessons learned.

## 8. Detection-engineering takeaway

A known-indicator rule for `WindowsHelper` or the malware hash can help find this exact known threat; it may miss renamed variants. A broader behavioral rule that evaluates service installations from suspicious paths alongside remote access and process telemetry can improve coverage, but also risks false positives. Validate with representative **true-positive, false-positive, false-negative, and true-negative** scenarios before deployment.

## 9. Reproducibility and limitations

This document reports a **fictional training scenario**, not captured production telemetry. It cannot be used to calculate real detection accuracy, prove an actual intrusion, or claim live incident response employment experience. SPL examples in this repository are draft educational searches whose field names, indexes, and detection behavior require verification in a suitable lab.

## 10. Ready summary

> In a guided simulation, I initially treated a chain of Administrator RDP, PowerShell, and service-installation events as suspicious rather than automatically malicious. After simulated EDR data and authorization checks confirmed unauthorized access, malicious service execution, and a known-malware hash match, I classified the scenario as a confirmed compromise. I kept the outbound connection classified as suspicious rather than asserting C2 or exfiltration without evidence.
