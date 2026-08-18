# Lateral Movement Investigation - SMB

## Objective
Detect and investigate potential lateral movement activity by identifying suspicious Server Message Block (SMB) connections and file share access between internal systems.

## Incident Scenario
A workstation was compromised after a phishing attack. The attacker used stolen administrator credentials to access internal SMB shares and move tools or malicious files across the network in an attempt to expand access within the environment.

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder
- Sysmon

## Data Sources / Log Sources
The investigation uses:
- Windows Security Event Logs
- SMB Operational Logs
- Sysmon Logs
- Firewall Logs

Important Event IDs:

- 4624 - Successful Logon
- 4625 - Failed Logon
- 4648 - Logon with Explicit Credentials
- 5140 - Network Share Object Accessed
- 5145 - Detailed File Share Access Check

## MITRE ATT&CK Mapping

- T1021 - Remote Services

Sub-techniques:

- T1021.002 - SMB/Windows Admin Shares

## Detection Logic

Trigger an alert when:

- SMB access originates from an unusual internal host
- Administrative shares such as ADMIN$, C$, IPC$ are accessed
- A privileged account accesses multiple systems within a short period
- Multiple SMB connections occur in a short time window
- Suspicious file transfers are detected through SMB shares

## Detection Rules

### Sigma Rule

The Sigma detection rule is available here:

```
[SMB.sigma.yml](SMB.sigma.yml)
```

## Query

### SPL (Splunk)

```spl
index=wineventlog (EventCode=5140 OR EventCode=5145)
| stats count values(Share_Name) as shares values(Account_Name) as usernames by WorkstationName, ComputerName
| where count >= 3
```

The SPL detection rule is available here:

```
[SMB.spl](SMB.spl)
```

### KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID in (5140,5145)
| summarize ShareAccess=count(), Shares=make_set(ShareName)
by Account, IpAddress, Computer, bin(TimeGenerated, 10m)
| where ShareAccess >= 3
```

## Investigation Steps

1. Identify the source workstation accessing SMB.
2. Identify the destination server and accessed share.
3. Review the account used for authentication.
4. Check accessed files and transferred objects.
5. Verify whether the activity was authorized.

## Timeline

```
10:00 - Initial workstation compromise
10:08 - SMB connection detected
10:12 - Multiple administrative shares accessed
10:15 - SIEM alert generated
```

## Findings

The investigation identified suspicious SMB access from a compromised workstation using privileged credentials, indicating possible lateral movement activity.

## False Positives

- System administrators
- Backup operations
- File server maintenance
- Authorized software deployment

## Response / Mitigation

- Isolate the compromised host
- Reset compromised credentials
- Restrict unnecessary SMB access
- Disable unused administrative shares
- Monitor privileged account activity

## Lessons Learned

- Limit SMB exposure
- Monitor administrative share access
- Apply least privilege principles
- Segment internal networks

## References

- MITRE ATT&CK T1021.002
- Windows Security Event Documentation

## Detection Validation

### Test Data

The detection was validated using simulated Windows Security Event 5140 and 5145 logs.

Sample log file:

```
[SMB.json](SMB.json)
```

## Test Case

- SMB connection detected
- Administrative share access
- Privileged account usage
- Multiple internal hosts
- Time window: 10 minutes

## Detection Improvements

Future improvements:

- Detect PsExec activity over SMB
- Correlate SMB activity with process creation
- Detect suspicious file execution after transfer
- Integrate threat intelligence

## Expected Result

SIEM should generate a lateral movement alert when suspicious SMB activity is detected.
