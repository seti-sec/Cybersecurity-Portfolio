# Persistence Investigation

## Objective
Detect and investigate potential persistence mechanisms by identifying suspicious scheduled task creation and execution on Windows systems.

## Incident Scenario
An attacker gained initial access to a workstation and created a scheduled task to execute malicious code automatically after system startup or at a specific time. The scheduled task allows the attacker to maintain access after reboot.

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
- Task Scheduler Logs

Important Event IDs:
4698 - Scheduled Task Created
4702 - Scheduled Task Updated
4699 - Scheduled Task Deleted
1 - Process Creation (Sysmon)

## MITRE ATT&CK Mapping
- T1053 - Scheduled Task/Job

Sub-techniques:
- T1053.005 - Scheduled Task

## Detection Logic
Trigger an alert when:
- A new scheduled task is created
- Task executes suspicious binaries
- Task runs from unusual locations
- Task is created by a non-administrative user

## Detection Rules

### Sigma Rule
The Sigma detection rule is available here:
[persistence_scheduled_task_detection_rule.yml](sigma/persistence_scheduled_task_detection_rule.yml)

## Query

### SPL (Splunk)

The SPL detection rule is available here:
[persistence_scheduled.spl](queries/persistence_scheduled.spl)

### KQL (Microsoft Sentinel)

SecurityEvent
| where EventID in (4698,4702,4699)

## Investigation Steps
1. Identify the created scheduled task.
2. Review task name and execution path.
3. Identify the user who created the task.
4. Check the executed process.
5. Investigate related network activity.

## Timeline
10:00 - Initial compromise detected
10:05 - Scheduled task created
10:10 - Task executed
10:15 - SIEM alert generated

## Findings
A suspicious scheduled task was created to execute an unknown program automatically, indicating a possible persistence mechanism.

## False Positives
* Legitimate administrator tasks
* Software update tasks
* Enterprise management tools

## Response / Mitigation
* Remove malicious scheduled tasks
* Isolate affected system
* Investigate user account activity
* Block malicious executables

## Lessons Learned
* Monitor scheduled task creation
* Restrict user privileges
* Enable process monitoring
* Improve endpoint visibility

## References
* MITRE ATT&CK T1053.005
* Windows Security Event Documentation

## Detection Validation

### Test Data
The detection was validated using simulated Windows Scheduled Task events.

Sample log file:
[persistence_scheduled.json](samples/persistence_scheduled.json)

### Test Case
- Scheduled task created
- Suspicious execution path
- Non-standard user activity

## Detection Improvements

Future improvements:
- Correlate scheduled tasks with process execution
- Detect persistence through registry run keys
- Add threat intelligence enrichment

### Expected Result
SIEM should generate a persistence alert when suspicious scheduled task activity is detected.
