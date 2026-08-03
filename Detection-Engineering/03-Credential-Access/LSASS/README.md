# Credential Access Investigation - LSASS

## Objective

Detect and investigate potential credential access activity by identifying suspicious access to the LSASS process.

## Incident Scenario

A workstation was compromised after a phishing attack. The attacker attempted to extract credentials from LSASS memory to obtain user passwords and authentication material.

## Environment

- Windows Server 2022
- Windows Security Logs
- Sysmon
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Sysmon Logs
- Windows Security Logs
- Endpoint Detection Logs

Important Event IDs:

- Sysmon Event ID 10 - Process Access
- Sysmon Event ID 1 - Process Creation

## MITRE ATT&CK Mapping

- T1003 - OS Credential Dumping

Sub-techniques:

- T1003.001 - LSASS Memory

## Detection Logic

Trigger an alert when:

- A process accesses LSASS memory
- Unknown processes request LSASS access rights
- Credential dumping behavior is observed

## Detection Rules

### Sigma Rule

LSASS.sigma.yml

## Query

### SPL (Splunk)

LSASS.spl

## Investigation Steps

1. Identify the process accessing LSASS.
2. Review process path and hash.
3. Identify the user context.
4. Check for credential dumping tools.
5. Verify whether activity is authorized.

## Timeline

10:00 - Initial compromise  
10:08 - LSASS memory access detected  
10:12 - Credential dumping behavior observed  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious access to LSASS memory, indicating possible credential dumping activity.

## False Positives

- Antivirus software
- EDR agents
- Security monitoring tools

## Response / Mitigation

- Isolate affected host
- Remove malicious tools
- Reset compromised credentials
- Review privileged accounts

## Lessons Learned

- Protect credential stores
- Enable LSASS protection
- Monitor process access events
- Apply least privilege

## Detection Validation

Sample log file:

LSASS.json

## Test Case

- LSASS process access detected
- Unknown source process
- Credential dumping behavior

## Expected Result

SIEM should generate an alert when suspicious LSASS access is detected.
