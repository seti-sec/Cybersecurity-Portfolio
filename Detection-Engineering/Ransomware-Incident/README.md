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

## Timeline

## Findings

## False Positives

## Response / Mitigation

## Lessons Learned

## References

## Detection Validation
