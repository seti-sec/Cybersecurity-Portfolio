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
1. Review the authentication events related to the alert.
2. Identify the source and destination systems involved.
3. Verify whether the user normally accesses these systems.
4. Analyze RDP and SMB activity.
5. Check for privileged account usage.
6. Review additional endpoint and network logs.
7. Determine whether the activity is legitimate or malicious.

## Detection Validation
### Test Data
The detection was validated using simulated lateral movement activity logs.
Sample log file:
[lateral_movement_activity.json](samples/lateral_movement_activity.json)
### Test Case
- Successful remote login detected
- RDP connection observed
- SMB access observed
- Privileged account activity detected
### Expected Result
SIEM should generate a lateral movement alert when abnormal remote access behavior is correlated.

## Timeline
| Time | Event |
|---|---|
| 12:00 | User logged into SERVER-01 using RDP |
| 12:05 | User accessed SERVER-02 through SMB |
| 12:05 | Privileged access assigned |
| 12:10 | SOC investigation started |

## Findings
- A privileged account accessed multiple internal systems.
- Remote services were used for movement inside the network.
- The activity requires validation against normal user behavior.
- Potential credential compromise should be investigated.

## False Positives
Possible false positives:
- System administrators performing maintenance.
- IT support remote sessions.
- Automated management tools.

## Response / Mitigation
- Validate the user's identity and activity.
- Disable compromised accounts if necessary.
- Reset credentials.- Isolate affected systems.
- Review access permissions.
- Block malicious remote access paths.

## Lessons Learned
- Remote services should be monitored continuously.
- Privileged account activity requires additional verification.
- Authentication events should be correlated across multiple systems.
- Unusual user behavior can indicate credential compromise.

## References
- MITRE ATT&CK T1021
- Remote Services- MITRE ATT&CK T1550.002
- Pass the Hash- Windows Security Event Documentation

## Detection Validation
### Test Data
The detection was validated using simulated lateral movement activity logs.
Sample log file:
lateral_movement_activity.json

### Test Case
- User authentication from an unusual source system- RDP remote access detected- SMB access between internal systems- Privileged account activity detected

### Expected Result
SIEM should generate a lateral movement alert when multiple suspicious authentication and remote access events are correlated.
