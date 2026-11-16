
# Detection Validation Test Cases

**Project:** SOC Detection Engineering & Threat Hunting  
**Environment:** Simulated Windows security telemetry  
**Status:** Test plan prepared; live Splunk validation pending

## 1. Purpose

This document describes how to validate the effectiveness of three proposed detections:

- DET-001: Suspicious RDP Authentication
- DET-002: Suspicious PowerShell Execution
- DET-003: Windows Service Persistence

The objective is to verify detection coverage, identify false positives and false negatives, and assess alert quality before recommending production deployment.

The test scenarios below are illustrative. They are not evidence that the SPL queries have been successfully executed or validated.

## 2. Detection Validation Concepts

| Classification | Meaning |
|---|---|
| True Positive (TP) | Malicious activity correctly triggers an alert |
| False Positive (FP) | Benign activity incorrectly triggers an alert |
| False Negative (FN) | Malicious activity occurs but is not detected |
| True Negative (TN) | Benign activity correctly produces no alert |

An alert matching a suspicious pattern is not automatically a true positive. Ground truth about whether the underlying activity is malicious or benign is required.

## 3. DET-001: Suspicious RDP Authentication

### Detection hypothesis

Multiple failed remote authentication attempts followed by successful authentication from the same source may indicate password guessing or unauthorized access.

### Proposed test cases

| ID | Scenario | Expected result |
|---|---|---|
| RDP-01 | Six failed Type 10 logons followed by one successful Type 10 logon within the same 15-minute bucket, same host, account and IP | Alert |
| RDP-02 | One failed logon followed by a successful logon | No alert |
| RDP-03 | Ten failures without a success | No alert from this specific rule |
| RDP-04 | Six failures followed by a successful logon from another IP | No combined alert |
| RDP-05 | Legitimate user mistypes a password six times, then succeeds | Alert possible; investigate as a false positive if activity is verified benign |
| RDP-06 | Failures and success fall across adjacent 15-minute buckets | Possible missed detection |

### Validation requirements

Check that:

- Event ID 4624 and 4625 records are ingested.
- Logon Type fields are correctly extracted.
- Source IP and account identities are normalized.
- The same host, account and source IP are grouped.
- Time ordering is assessed correctly.
- Adjacent time-window boundary behavior is tested.
- Successful access is not automatically classified as compromise.

### Known limitations

The current fixed-window rule may miss activity crossing time boundaries.

It also does not cover every form of RDP authentication, distributed password spraying, or attacks involving a single successful credential use.

## 4. DET-002: Suspicious PowerShell Execution

### Detection hypothesis

PowerShell activity containing selected potentially dangerous execution patterns may warrant investigation.

### Proposed test cases

| ID | Scenario | Expected behavior |
|---|---|---|
| PS-01 | Encoded PowerShell command appears in captured process command line | Indicator match expected |
| PS-02 | Script-block content contains remote content retrieval | Indicator match expected, subject to rule syntax |
| PS-03 | Approved administration script contains a flagged term | Possible false positive |
| PS-04 | Malicious PowerShell uses an unrecognized execution pattern | Possible false negative |
| PS-05 | Script Block Logging is not enabled | Reduced coverage |
| PS-06 | PowerShell process creation is recorded without command-line arguments | Reduced detection context |

### Validation requirements

Confirm that:

- Security Event 4688 collection is available.
- Command-line logging is enabled where required.
- PowerShell Event 4104 telemetry is available where configured.
- Relevant field extractions contain the expected command content.
- Regular expressions match the intended patterns.
- Event sources are identified correctly.
- Approved administrative activity is evaluated against change records.
- Alert severity reflects evidence rather than keywords alone.

### Known limitations

Encoded commands, download commands, and execution-policy options are not exclusively malicious.

Event 4104 records script-block content; it does not independently prove successful completion of every operation described.

## 5. DET-003: Windows Service Persistence

### Detection hypothesis

A newly installed service referencing a suspicious executable location or script interpreter may indicate an attempt to establish persistence.

### Proposed test cases

| ID | Scenario | Expected behavior |
|---|---|---|
| SVC-01 | New service points to C:\Users\Public\helper.exe | Suspicious-path indicator |
| SVC-02 | New service references an AppData executable | Suspicious-path indicator |
| SVC-03 | Approved vendor installs a service in Program Files | Usually no suspicious-path indicator |
| SVC-04 | Approved deployment uses a temporary directory | Possible false positive |
| SVC-05 | Attacker installs a malicious service in a trusted-looking location | Possible false negative |
| SVC-06 | Service installation is observed, but no start telemetry is available | Installation established; execution unconfirmed |

### Validation requirements

Check:

- System Event 7045 ingestion.
- Service name and executable-path extraction.
- Recognition of quoted paths and command-line arguments.
- Handling of environment variables and alternate path forms.
- Detection of suspicious script interpreter usage.
- Whether approved software deployments trigger alerts.
- Whether additional telemetry confirms service execution.
- Whether the configured risk score is useful for prioritization.

### Known limitations

Event 7045 records service installation, not proof of malicious intent or successful executable launch.

Additional evidence may include service state changes, process telemetry, executable hashes, signatures, endpoint alerts, and authorization records.

## 6. Test Execution Worksheet

For each test, record:

| Field | Description |
|---|---|
| Test ID | Unique scenario identifier |
| Detection | Rule being tested |
| Test date | Date and time |
| Dataset | Location or identifier of test data |
| Ground truth | Independently established malicious or benign classification |
| Expected result | Intended alert or non-alert |
| Actual result | Observed detection behavior |
| Classification | TP, FP, FN or TN |
| Analyst notes | Explanation of the outcome |
| Required changes | Rule improvements or tuning |

Do not fill in actual results until a test has been executed and its outcome verified.

## 7. Evaluation Metrics

Precision measures the proportion of alerts that are genuinely malicious:

Precision = TP / (TP + FP)

Recall measures the proportion of malicious activity detected:

Recall = TP / (TP + FN)

False-positive rate measures benign cases that incorrectly alert:

FPR = FP / (FP + TN)

These measures require labeled test data. No numerical performance claims are made for the current detections.

## 8. Production Readiness Checklist

- [ ] Verify Splunk search syntax.
- [ ] Confirm relevant indexes and sourcetypes.
- [ ] Validate field extractions and normalization.
- [ ] Execute known malicious test scenarios.
- [ ] Execute known benign test scenarios.
- [ ] Assess time-window and missing-telemetry limitations.
- [ ] Evaluate false-positive patterns.
- [ ] Confirm alert output includes adequate investigation context.
- [ ] Review performance and expected alert volume.
- [ ] Document tuning decisions and obtain required approval.

## 9. Current Assessment

All three proposed detections remain educational examples.

The scenarios define expected behavior, but their outcomes have not been experimentally verified in a live Splunk environment.

Before production deployment, the SPL searches must be tested against representative telemetry, and their performance and alert quality must be measured.

## 10. Lessons Learned

Detection engineering requires more than writing queries.

Effective detections depend on:

1. Reliable telemetry.
2. Correct field extraction.
3. Meaningful behavioral hypotheses.
4. Proper time and entity correlation.
5. Ground-truth validation.
6. False-positive investigation.
7. Clear documentation.
8. Continuous improvement.

---

**Disclaimer:** This document is a detection validation plan developed through cybersecurity training. It does not claim production testing or confirmed detection performance.
