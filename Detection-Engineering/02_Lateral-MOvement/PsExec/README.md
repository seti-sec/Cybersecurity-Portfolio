# Lateral Movement Investigation - PsExec

## Objective
Detect and investigate potential lateral movement activity by identifying suspicious remote service creation and process execution associated with PsExec.

## Incident Scenario
A workstation was compromised after a phishing attack. The attacker used stolen administrator credentials and PsExec to execute commands remotely on internal systems and expand access.

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder
- Sysmon

## Data Sources / Log Sources

The investigation uses:

- Windows Security Logs
- System Event Logs
- Sysmon Logs
- Service Creation Logs

Important Event IDs:

- 4624 - Successful Logon
- 4648 - Logon with Explicit Credentials
- 4688 - Process Creation
- 7045 - Service Creation

## MITRE ATT&CK Mapping

- T1021 - Remote Services
- T1569 - System Services

Sub-techniques:

- T1569.002 - Service Execution

## Detection Logic

Trigger an alert when:

- A suspicious service is created remotely
- PSEXESVC service appears
- Remote process execution occurs
- Administrative credentials are used from unusual hosts

## Detection Rules

### Sigma Rule

PsExec.sigma.yml

## Query

### SPL (Splunk)

PsExec.spl

## Investigation Steps

1. Identify the source workstation.
2. Identify the destination system.
3. Review created services.
4. Analyze executed processes.
5. Verify administrative activity.

## Timeline

10:00 - Initial workstation compromise  
10:08 - Remote service creation detected  
10:12 - PsExec execution observed  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious PsExec activity using privileged credentials, indicating possible lateral movement.

## False Positives

- System administrators
- Software deployment systems
- Remote management tools

## Response / Mitigation

- Isolate compromised host
- Reset privileged credentials
- Restrict remote service execution
- Monitor administrative activity

## Lessons Learned

- Monitor service creation events
- Limit privileged account usage
- Apply network segmentation

## Detection Validation

Sample log file:

PsExec.json

## Test Case

- Remote service creation
- PSEXESVC detection
- Privileged account usage
- Internal host communication

## Expected Result

SIEM should generate a lateral movement alert when suspicious PsExec activity is detected.
