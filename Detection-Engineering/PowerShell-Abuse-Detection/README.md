# PowerShell Abuse Detection

## Objective

Detect and investigate suspicious PowerShell activity that may indicate execution of malicious commands, script abuse, or attacker activity inside the environment.

## Incident Scenario

A SOC analyst receives an alert for suspicious PowerShell execution on an endpoint.

During investigation, the security team identifies PowerShell commands containing encoded content and suspicious execution patterns.

The attacker is using PowerShell as a living-off-the-land technique to execute malicious scripts and evade traditional security controls.

## Environment

- Windows Server 2022
- Windows PowerShell
- Windows Security Logs
- Sysmon
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Windows PowerShell Logs
- Sysmon Logs
- Windows Security Event Logs

Important Event IDs:

4104 - PowerShell Script Block Logging
4688 - Process Creation

## MITRE ATT&CK Mapping

T1059 - Command and Scripting Interpreter

Sub-techniques:

T1059.001 - PowerShell

## Detection Logic

Trigger an alert when:

- PowerShell execution is detected
- Script Block Logging contains suspicious keywords
- Encoded PowerShell commands are executed
- PowerShell connects to external resources
- Unusual PowerShell activity is performed by a user or endpoint

## Query

### SPL (Splunk)

The SPL detection rule is available here:

[powershell_abuse_detection.spl](queries/powershell_abuse_detection.spl)

## Investigation Steps

## Timeline

## Findings

## False Positives

## Response / Mitigation

## Lessons Learned

## Detection Validation

### Test Data

The detection was validated using simulated PowerShell event logs.
Sample log file:
[powershell_abuse_sample.json](samples/powershell_abuse_sample.json)

### Test Case

### Expected Result

## References
