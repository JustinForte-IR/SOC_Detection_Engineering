
# MITRE ATT&CK Mapping — Windows Incident Investigation

**Project:** SOC Detection Engineering & Threat Hunting  
**Scenario:** SRV-02 — Unauthorized RDP Access and Malicious Windows Service  
**Evidence type:** Simulated enterprise incident  
**Status:** Training case study; mappings based on stated scenario evidence

## 1. Objective

Map behaviors identified during a simulated Windows Server compromise to relevant MITRE ATT&CK techniques.

The purpose is to demonstrate evidence-based ATT&CK analysis, support detection engineering, and identify additional investigation opportunities.

An event ID alone does not establish an ATT&CK technique. Mappings should be supported by the behavior described in the available evidence.

## 2. Incident Summary

The simulated incident began with unauthorized Administrator RDP access to SRV-02.

Subsequent telemetry showed PowerShell activity associated with the Administrator logon, service-creation activity, and installation of a service named `WindowsHelper`.

Additional EDR evidence established that the service launched `C:\Users\Public\helper.exe` under SYSTEM.

The executable's SHA-256 hash matched a confirmed malware sample, and the system owner and security team confirmed that the access and service installation were unauthorized.

An outbound connection was also observed, but its purpose was not established.

**Incident classification:** Confirmed security compromise within the simulated scenario.

## 3. ATT&CK Technique Mapping

| ATT&CK ID | Technique | Evidence | Assessment |
|---|---|---|---|
| T1078 | Valid Accounts | Unauthorized access using the Administrator account | Supported |
| T1021.001 | Remote Desktop Protocol | Successful RDP session | RDP behavior established; access/lateral-movement context requires care |
| T1059.001 | PowerShell | PowerShell process and related execution telemetry | Supported |
| T1543.003 | Windows Service | Unauthorized malicious service creation and execution | Supported |
| Not assigned | Command and Control | Unrecognized outbound connection | Insufficient evidence for a specific C2 technique |
| Not assigned | Exfiltration | No confirmed data transfer or exfiltration behavior | Not established |

## 4. Technique Analysis

### T1078 — Valid Accounts

**Tactic:** May support Initial Access, Persistence, Privilege Escalation, or Defense Evasion, depending on context.

Evidence:
- Administrator credentials were used during an RDP logon.
- The system owner and security team confirmed the activity was unauthorized.

Assessment:

The scenario supports abuse of a valid account.

Further investigation should establish how the credentials were obtained, whether other accounts were affected, and whether the account was used on additional hosts.

Unauthorized credential use does not, by itself, prove how credentials were compromised.

### T1021.001 — Remote Desktop Protocol

**Tactic:** Lateral Movement.

Evidence:
- Windows Event 4624 recorded a RemoteInteractive logon.
- RDP-related telemetry supported successful remote access.

Assessment:

Use of RDP is established. Mapping the activity to T1021.001 requires appropriate context about the adversary's use of remote services.

The scenario does not independently establish lateral movement from another compromised host.

Additional investigation should consider:
- Source-host ownership.
- Prior compromise of the source.
- Approved remote-access architecture.
- Related remote sessions and account activity.

### T1059.001 — PowerShell

**Tactic:** Execution.

Evidence:
- Event 4688 recorded PowerShell process creation.
- Event 4104 captured relevant script-block content.
- EDR linked the PowerShell process to a service-creation command.

Assessment:

The combined evidence supports PowerShell being used during the malicious activity.

Important distinction:

Event 4104 records script-block content, but script text alone does not prove that every operation completed successfully.

The scenario's EDR and service-installation records provide additional evidence about the actual service-creation behavior.

### T1543.003 — Windows Service

**Tactics:** Persistence and Privilege Escalation.

Evidence:
- Event 7045 recorded installation of `WindowsHelper`.
- Event 7036 showed the service entering the Running state.
- EDR confirmed that `services.exe` launched `helper.exe` under SYSTEM.
- The executable matched confirmed malware.
- Installation was unauthorized.

Assessment:

The evidence supports malicious Windows service creation and execution.

The service-based mechanism is consistent with persistence. Execution as SYSTEM establishes high-privilege execution, although the precise privilege-escalation pathway should not be assumed without additional evidence.

Event 7045 alone would establish installation, not maliciousness or executable launch.

## 5. Outbound Network Activity — Unresolved

The malware process initiated an outbound connection to an external IP that was not identified as approved.

This warrants further investigation.

However, an outbound connection alone does not prove:
- Command-and-control.
- Data exfiltration.
- Successful receipt of attacker commands.
- The transmission of sensitive information.

Recommended follow-up:
1. Identify destination IP, port, protocol, and associated domain.
2. Review DNS, firewall, proxy, and endpoint network telemetry.
3. Investigate connection timing relative to malware execution.
4. Examine available traffic metadata and packet captures.
5. Assess destination intelligence and known malware behavior.
6. Determine whether a specific ATT&CK network technique is supported.

No C2 or exfiltration technique is assigned in this report because the current evidence does not justify one.

## 6. Detection Opportunities

| Detection | Relevant telemetry | Objective |
|---|---|---|
| Suspicious RDP authentication | 4624, 4625, RDP session logs | Identify unusual remote access patterns |
| Suspicious PowerShell execution | 4688, 4104, EDR | Identify risky execution behavior |
| Suspicious service installation | 7045, 7036, EDR | Identify potential service-based persistence |
| Multi-event correlation | Authentication, process, service telemetry | Increase confidence through contextual evidence |
| Malware hash hunting | EDR, file inventory, threat intelligence | Identify other hosts containing the known malicious executable |

These are proposed investigative opportunities, not claims that all detection rules have been successfully tested.

## 7. Evidence Confidence and Limitations

### Confirmed within the simulation
- Unauthorized Administrator RDP access.
- Associated PowerShell execution.
- Unauthorized service installation.
- Malware executable launched under SYSTEM.
- Hash match to confirmed malware.

### Not established
- Initial credential acquisition method.
- Lateral movement from another compromised system.
- Exact purpose of outbound communication.
- Confirmed command-and-control.
- Confirmed data exfiltration.
- Complete scope of affected systems.

A strong ATT&CK mapping explicitly records these limitations.

## 8. Lessons Learned

1. Map observed behaviors, not event IDs in isolation.
2. Differentiate suspicious signals from confirmed malicious actions.
3. Distinguish service installation from service execution.
4. Use multiple sources to establish execution relationships.
5. Do not infer lateral movement solely from RDP access.
6. Do not classify every suspicious outbound connection as C2.
7. Revise technique mappings as new evidence becomes available.

## 9. References

- MITRE ATT&CK: https://attack.mitre.org/
- T1078: https://attack.mitre.org/techniques/T1078/
- T1021.001: https://attack.mitre.org/techniques/T1021/001/
- T1059.001: https://attack.mitre.org/techniques/T1059/001/
- T1543.003: https://attack.mitre.org/techniques/T1543/003/

---

**Disclaimer:** This report uses simulated evidence from a guided cybersecurity training scenario. It does not represent a real-world compromise investigation or verified production SOC work.
