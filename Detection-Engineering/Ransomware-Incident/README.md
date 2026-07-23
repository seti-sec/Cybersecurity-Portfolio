# Ransomware Incident Investigation

## Objective
Detect and investigate ransomware activity by identifying suspicious file encryption behavior, abnormal processes, and indicators of compromise.
## Incident Scenario
A user reports that multiple files on their workstation have become inaccessible and their extensions have changed.
The SOC team investigates endpoint activity, running processes, file modification events, and network communication to determine whether a ransomware attack occurred.
## Environment
- Windows Endpoints
- EDR Solution- SIEM (Splunk)
- File Servers- Network Monitoring Tools
## Data Sources / Log Sources
The investigation uses the following data sources:
- Windows Event Logs
- Sysmon Logs
- EDR Telemetry
- File System Activity Logs
- Process Creation Logs
- Network Traffic Logs
- Authentication Logs
  
Important data points:
- File encryption activity
- Suspicious process execution
- Unusual file extensions
- Process command line
- Parent-child process relationship
- External network connections

## MITRE ATT&CK Mapping
### Techniques:
- T1486 - Data Encrypted for Impact
- T1059 - Command and Scripting Interpreter
- T1083 - File and Directory Discovery
- T1047 - Windows Management Instrumentation (WMI)

## Detection Logic
Generate an alert when ransomware-like behavior is detected.
Detection conditions:
- A process modifies a large number of files in a short period of time.
- Multiple files receive suspicious extensions.
- A suspicious process creates high-volume file write activity.
- A process shows abnormal parent-child relationships.
- Endpoint communicates with known suspicious destinations.
Example correlation:
- File modification activity
- Process creation event
- Network connection event

## Query
### SPL (Splunk)
The SPL detection rule is available here:
[ransomware_detection.spl](queries/ransomware_detection.spl)
### KQL (Microsoft Sentinel)
```kql
DeviceFileEvents
| summarize FileChanges=count() by InitiatingProcessFileName
| where FileChanges > 100

## Investigation Steps
1. Review the alert details and identify the affected endpoint.
2. Analyze the suspicious process that performed file modifications.
3. Check process creation logs and command-line activity.
4. Review file modification events and identify affected files.
5. Investigate network connections made by the suspicious process.
6. Check if other endpoints show similar ransomware behavior.
7. Determine the scope of impact and affected users.
8. Collect forensic evidence for further analysis.

## Timeline
| Time | Event ||---|---|| 11:00 | Suspicious process started modifying files || 11:00 | Multiple files received encrypted extensions || 11:00 | Suspicious outbound network connection detected || 11:05 | SOC investigation started |

## Findings
- A suspicious executable performed high-volume file modifications.
- Multiple files were encrypted and renamed.
- The process created suspicious network communication.
- Behavior matched ransomware activity patterns.

## False Positives
- Legitimate backup software modifying many files.
- Software updates changing multiple files.
- File synchronization tools.

## Response / Mitigation
- Isolate the affected endpoint from the network.
- Stop the malicious process.
- Collect forensic evidence.
- Reset compromised credentials.
- Restore files from clean backups.
- Block indicators of compromise.

## Lessons Learned
- MITRE ATT&CK T1486
- Data Encrypted for Impact
- Microsoft Security Documentation
- Ransomware Detection Best Practices

## References
1. Review the alert details and identify the affected endpoint.
2. Analyze the suspicious process that performed file modifications.
3. Check process creation logs and command-line activity.
4. Review file modification events and identify affected files.
5. Investigate network connections made by the suspicious process.
6. Check if other endpoints show similar ransomware behavior.
7. Determine the scope of impact and affected users.
8. Collect forensic evidence for further analysis.

## Detection Validation
### Test Data
The detection was validated using simulated ransomware activity logs.
Sample log file:
[ransomware_activity.json](samples/ransomware_activity.json)
### Test Case
- Suspicious file encryption activity detected
- Unknown process modifies multiple files
- Process creates outbound network connection
### Expected Result
SIEM should generate a ransomware alert when multiple suspicious behaviors are correlated.
