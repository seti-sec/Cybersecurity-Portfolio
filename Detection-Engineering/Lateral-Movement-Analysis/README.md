# Lateral Movement Analysis

## Objective
Detect and investigate lateral movement activities where an attacker moves from an initially compromised system to other systems inside the network.

## Incident Scenario
A user account is compromised through an initial attack.
The attacker uses valid credentials to access other internal systems through remote services such as RDP or SMB.
The SOC team investigates authentication logs, remote connections, and abnormal user behavior to identify the attack path.

## Environment
- Windows Domain Environment
- Active Directory- Windows Servers
- SIEM (Splunk)
- Endpoint Detection and Response (EDR)

## Data Sources / Log Sources
The investigation uses the following data sources:
- Windows Security Event Logs
- Active Directory Logs
- Sysmon Logs- VPN Logs
- Firewall Logs
- EDR Telemetry
Important Event IDs:
- 4624 - Successful Logon
- 4625 - Failed Logon
- 4672 - Special Privileges Assigned
- 4648 - Logon Attempt Using Explicit Credentials

## MITRE ATT&CK Mapping
### Techniques:
- T1021 - Remote Services
- T1021.001
- Remote Desktop Protocol (RDP)
- T1021.002 - SMB/Windows Admin Shares
- T1550.002
- Pass the Hash

## Detection Logic
Generate an alert when suspicious lateral movement behavior is detected.
Detection conditions:
- A user logs into multiple internal systems within a short time period.
- A login occurs from an unusual source workstation.
- Remote services such as RDP or SMB are used unexpectedly.
- Privileged accounts perform remote access activities.
- Multiple authentication events indicate possible credential misuse.
- 
Correlation example:
- Successful logon event (4624)
- Source workstation
- Destination system
- User account
- Remote service type

## Query
### SPL (Splunk)
The SPL detection rule is available here:
[lateral_movement_detection.spl](queries/lateral_movement_detection.spl)
### KQL (Microsoft Sentinel)
```kql
SecurityEvent
| where EventID == 4624
| summarize LoginCount=count(), Computers=dcount(Computer) by Account
| where Computers > 3

## Investigation Steps

## Timeline

## Findings

## False Positives

## Response / Mitigation

## Lessons Learned

## References

## Detection Validation
