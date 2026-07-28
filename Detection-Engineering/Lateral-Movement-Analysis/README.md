# Lateral Movement Investigation

## Objective
Detect and investigate potential lateral movement activity by identifying suspicious Remote Desktop Protocol (RDP) connections between internal systems.

## Incident Scenario
A workstation was compromised after a phishing attack. The attacker used stolen administrator credentials to access multiple internal servers via Remote Desktop Protocol (RDP) in an attempt to expand access within the environment.

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder
- Sysmon

## Data Sources / Log Sources
The investigation uses:
- Windows Security Event Logs
- Terminal Services Logs
- Sysmon Logs
- Firewall Logs

Important Event IDs:
4624 - Successful Logon
4625 - Failed Logon
4648 - Logon with Explicit Credentials
4778 - RDP Session Reconnected
4779 - RDP Session Disconnected

## MITRE ATT&CK Mapping
- T1021 - Remote Services

Sub-techniques:
- T1021.001 - Remote Desktop Protocol (RDP)

## Detection Logic
Trigger an alert when:
- RDP logon (Logon Type 10)
- Administrative account is used
- Connection originates from an unusual internal host
- Multiple RDP sessions occur within a short period

## Detection Rules

### Sigma Rule
The Sigma detection rule is available here:
[lateral_movement_detection_rule.yml](sigma/lateral_movement_detection_rule.yml)

## Query

### SPL (Splunk)

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| stats count values(Account_Name) as usernames by ComputerName, WorkstationName
| where count >= 3
```

The SPL detection rule is available here:
[lateral_movement_detection.spl](queries/lateral_movement_detection.spl)

### KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| summarize LogonCount=count(), Hosts=make_set(Computer)
by Account, IpAddress, bin(TimeGenerated, 10m)
| where LogonCount >= 3
```

## Investigation Steps
1. Identify the source host.
2. Identify the destination host.
3. Review the account used.
4. Verify whether the activity is authorized.
5. Check for additional lateral movement activity.

## Timeline
10:00 - Initial workstation compromise
10:08 - First RDP connection detected
10:12 - Multiple RDP sessions observed
10:15 - SIEM alert generated

## Findings
The investigation identified multiple RDP logons from a compromised workstation to internal servers using an administrative account, indicating possible lateral movement.

## False Positives
* System administrators
* Helpdesk remote support
* Authorized maintenance activities

## Response / Mitigation
* Isolate the compromised host
* Disable or reset compromised credentials
* Restrict RDP access
* Review privileged account activity
* Enable MFA for administrative accounts

## Lessons Learned
* Limit RDP exposure
* Monitor privileged logons
* Implement network segmentation
* Enhance lateral movement detection rules

## References
* MITRE ATT&CK T1021
* Windows Security Event Documentation

## Detection Validation

### Test Data
The detection was validated using simulated Windows Security Event 4624 logs.

Sample log file:
[lateral_movement_activity.json](samples/lateral_movement_activity.json)

### Test Case
- Successful RDP logon
- Logon Type 10
- Administrative account
- Multiple internal hosts
- Time window: 10 minutes

## Detection Improvements

Future improvements:
- Detect PsExec activity
- Detect WMI lateral movement
- Correlate with PowerShell execution
- Integrate threat intelligence

### Expected Result
SIEM should generate a lateral movement alert when suspicious RDP activity is detected.

## References
