
# SOC Detection Engineering & Threat Hunting

**Project Type:** Cybersecurity training portfolio  
**Focus:** SOC Operations, Detection Engineering, Threat Hunting  
**Tools and Concepts:** Splunk SPL, Windows Event Logs, PowerShell, MITRE ATT&CK, Incident Response

## Project Overview

This repository documents practical detection engineering and threat-hunting exercises developed during my cybersecurity training.

The project focuses on analyzing Windows security telemetry, developing correlation searches, investigating suspicious administrative activity, and documenting evidence-based security findings.

The goal is to demonstrate how security analysts can convert individual log events into meaningful investigation hypotheses and actionable alerts.

## Key Objectives

- Develop security detections using Splunk Search Processing Language (SPL).
- Investigate suspicious RDP authentication activity.
- Correlate authentication, process creation, PowerShell, and service installation events.
- Identify potentially suspicious Windows persistence mechanisms.
- Understand false positives, false negatives, and detection coverage gaps.
- Apply MITRE ATT&CK mappings to supported behaviors.
- Document incident findings and escalation recommendations.

## Security Telemetry

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Windows logon |
| 4625 | Failed Windows logon |
| 4688 | Process creation |
| 4104 | PowerShell script-block logging |
| 7045 | Windows service installation |
| 7036 | Windows service state change |

These events provide useful investigative signals, but no single event automatically proves malicious activity.

## Detection Engineering Exercises

### 1. Suspicious RDP Activity

Investigate remote authentication activity and correlate relevant logon events with subsequent host behavior.

### 2. PowerShell Execution

Identify potentially suspicious PowerShell execution using process creation and script-block telemetry where available.

### 3. Windows Service Persistence

Investigate service installation events, suspicious executable locations, and related process execution.

## Threat Hunting Methodology

The hunting exercises follow a structured workflow:

1. Develop a threat hypothesis.
2. Identify relevant telemetry.
3. Build and refine an SPL query.
4. Examine matching events.
5. Correlate activity across available data sources.
6. Identify alternative benign explanations.
7. Document findings and evidence gaps.
8. Recommend escalation or additional investigation when justified.

## Detection Validation

The project examines:

- True positives (TP)
- False positives (FP)
- False negatives (FN)
- True negatives (TN)
- Detection precision and coverage
- Field normalization
- Data availability and retention
- Alert prioritization

A query returning events does not automatically mean a detection is effective.

## MITRE ATT&CK

Relevant techniques explored include:

- T1078 - Valid Accounts
- T1021.001 - Remote Desktop Protocol
- T1059.001 - PowerShell
- T1543.003 - Windows Service

ATT&CK mappings are applied only where the available evidence supports the associated behavior.

## Simulated Incident Case Study

The capstone investigates a hypothetical Windows Server scenario involving:

- Unauthorized Administrator RDP access
- PowerShell execution
- Windows service installation
- Execution of a malicious executable as SYSTEM
- Suspicious outbound network communication

The exercise demonstrates how new evidence can change an initial assessment into a confirmed compromise.

The purpose of the outbound communication remains unverified, so command-and-control and data exfiltration are not automatically considered confirmed.

**Important:** This case study uses simulated incident evidence. It is not a claim of investigating a real organizational breach.

## Repository Structure

```text
SOC_Detection_Engineering/
├── README.md
├── detections/
│   ├── suspicious-rdp-activity.spl
│   ├── powershell-execution.spl
│   └── service-persistence.spl
├── hunting/
│   └── threat-hunting-report.md
├── scenarios/
│   └── simulated-incident.md
├── validation/
│   └── detection-test-cases.md
└── mitre/
    └── attack-mapping.md
```

## Current Limitations

The detection queries are training examples and have not yet been independently validated against representative malicious and benign telemetry in a live Splunk environment.

Search field names, indexes, event sources, and time ranges must be adapted to the destination environment.

Additional testing is required before any rule can be considered production-ready.

## Skills Demonstrated

- Security event analysis
- Windows authentication investigations
- SIEM search development
- Multi-event correlation
- Detection logic and false-positive analysis
- Threat hunting methodology
- MITRE ATT&CK mapping
- Incident triage and reporting
- Evidence-based investigative reasoning


---

**Disclaimer:** This repository is an educational cybersecurity portfolio created through guided training and simulated scenarios. It does not represent production SOC employment experience or independently validated enterprise detections.
