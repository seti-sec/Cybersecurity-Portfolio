# Persistence Investigation - Scheduled Task

## Objective

Detect and investigate persistence activity by identifying suspicious Windows Scheduled Task creation.

## Incident Scenario

A compromised workstation was used by an attacker to create scheduled tasks that execute malicious programs automatically and maintain persistence after reboot.

## Environment

- Windows Server 2022
- Windows Security Logs
- Sysmon
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Windows Security Logs
- Task Scheduler Logs
- Sysmon Logs

Important Event IDs:

- 4698 - Scheduled Task Created
- 4699 - Scheduled Task Deleted
- 4700 - Scheduled Task Enabled
- 4702 - Scheduled Task Updated

## MITRE ATT&CK Mapping

- T1053 - Scheduled Task/Job

Sub-techniques:

- T1053.005 - Scheduled Task

## Detection Logic

Trigger an alert when:

- A new scheduled task is created
- A suspicious task executes from unusual paths
- A scheduled task is created by unexpected users

## Detection Rules

### Sigma Rule

Scheduled.sigma.yml

## Query

### SPL (Splunk)

Scheduled.spl

## Investigation Steps

1. Identify the created task.
2. Review task execution path.
3. Identify the creating user.
4. Check binary reputation.
5. Verify whether task creation was authorized.

## Timeline

10:00 - Initial compromise  
10:08 - Scheduled task created  
10:12 - Persistence mechanism detected  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious scheduled task creation, indicating possible persistence activity.

## False Positives

- Administrators
- Software deployment systems
- Enterprise automation

## Response / Mitigation

- Remove malicious scheduled tasks
- Block malicious binaries
- Reset compromised accounts
- Review persistence mechanisms

## Lessons Learned

- Monitor scheduled task creation
- Audit privileged users
- Restrict unnecessary administrative access

## Detection Validation

Sample log file:

Scheduled.json

## Test Case

- Scheduled task creation detected
- Unexpected user account
- Suspicious execution path

## Expected Result

SIEM should generate an alert when suspicious scheduled task persistence is detected.
