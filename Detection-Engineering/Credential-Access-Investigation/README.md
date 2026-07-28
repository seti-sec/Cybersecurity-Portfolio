# Credential Access Investigation

## Objective
Detect and investigate potential credential dumping activity by identifying suspicious attempts to access credentials stored on Windows systems.

## Incident Scenario
An attacker gained access to a Windows workstation and attempted to extract credentials from the operating system memory to obtain usernames and password hashes for further attacks.

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder
- Sysmon

## Data Sources / Log Sources
The investigation uses:
- Windows Security Event Logs
- Sysmon Logs
- Endpoint Detection Logs

Important Event IDs:
4688 - Process Creation
4656 - Handle Requested
4663 - Object Access

Sysmon Events:
1 - Process Creation
10 - Process Access

## MITRE ATT&CK Mapping
- T1003 - OS Credential Dumping

Sub-techniques:
- T1003.001 - LSASS Memory
- T1003.002 - Security Account Manager

## Detection Logic
Trigger an alert when:
- A suspicious process accesses LSASS memory
- Credential dumping tools are executed
- Unusual processes request access to protected processes
- Sensitive credential files are accessed

## Detection Rules

### Sigma Rule
The Sigma detection rule is available here:
[credential_dumping_detection_rule.yml](sigma/credential_dumping_detection_rule.yml)

## Query

### SPL (Splunk)

The SPL detection rule is available here:
[credential_dumping_detection.spl](queries/credential_dumping_detection.spl)

### KQL (Microsoft Sentinel)

SecurityEvent
| where EventID == 4688

## Investigation Steps
1. Identify the suspicious process.
2. Check the parent process.
3. Review the user account executing the process.
4. Investigate LSASS access activity.
5. Check for known credential dumping tools.

## Timeline
10:00 - Suspicious process execution detected
10:05 - LSASS access observed
10:10 - SIEM alert generated

## Findings
A suspicious process attempted to access credential-related resources, indicating possible credential dumping activity.

## False Positives
* Security tools
* Antivirus software
* Endpoint monitoring agents

## Response / Mitigation
* Isolate affected endpoint
* Terminate malicious process
* Reset compromised credentials
* Review privileged accounts

## Lessons Learned
* Enable LSASS protection
* Monitor credential access behavior
* Apply least privilege
* Improve endpoint visibility

## References
* MITRE ATT&CK T1003
* Windows Security Event Documentation
