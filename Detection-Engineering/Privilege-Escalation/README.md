# Privilege Escalation Investigation

## Objective
Detect and investigate potential privilege escalation activity by identifying users who obtain elevated privileges on Windows systems.

## Incident Scenario
An attacker gained access to a standard user account through phishing. Shortly after the initial compromise, the account was added to the local Administrators group, allowing the attacker to execute privileged actions.

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
- Active Directory Logs

Important Event IDs:
4672 - Special Privileges Assigned
4728 - Member Added to Security-Enabled Global Group
4732 - Member Added to Local Security Group
4670 - Permissions Changed

## MITRE ATT&CK Mapping
- T1068 - Exploitation for Privilege Escalation
- T1078 - Valid Accounts

## Detection Logic
Trigger an alert when:
- A user receives administrative privileges
- A privileged group membership changes
- Special privileges are assigned unexpectedly
- Activity occurs outside normal administrative hours

## Detection Rules

### Sigma Rule
The Sigma detection rule is available here:
[privilege_escalation_detection_rule.yml](sigma/privilege_escalation_detection_rule.yml)

## Query

### SPL (Splunk)

index=wineventlog (EventCode=4672 OR EventCode=4732 OR EventCode=4728)

The SPL detection rule is available here:
[privilege_escalation_detection.spl](queries/privilege_escalation_detection.spl)

### KQL (Microsoft Sentinel)

SecurityEvent
| where EventID in (4672,4728,4732)

## Investigation Steps
1. Identify the affected account.
2. Review privilege assignment.
3. Verify authorization.
4. Investigate previous user activity.
5. Check for persistence mechanisms.

## Timeline
10:00 - Initial compromise
10:08 - Privileges assigned
10:10 - SIEM alert generated

## Findings
A standard user account received administrative privileges shortly after compromise, indicating possible privilege escalation.

## False Positives
* Legitimate administrator actions
* Scheduled maintenance
* Authorized account provisioning

## Response / Mitigation
* Remove unauthorized privileges
* Reset credentials
* Review privileged groups
* Investigate compromised systems

## Lessons Learned
* Monitor privileged group changes
* Limit administrative privileges
* Enable least privilege
* Improve auditing

## References
* MITRE ATT&CK T1068
* Windows Security Event Documentation

## Detection Validation

### Test Data
The detection was validated using simulated Windows Security logs.

Sample log file:
[privilege_escalation.json](samples/privilege_escalation.json)

### Test Case
- User added to Administrators
- Event ID 4732
- Administrative privileges assigned

## Detection Improvements

Future improvements:
- Detect token manipulation
- Correlate with process creation
- Add threat intelligence enrichment

### Expected Result
SIEM should generate an alert when unauthorized privilege escalation is detected.
