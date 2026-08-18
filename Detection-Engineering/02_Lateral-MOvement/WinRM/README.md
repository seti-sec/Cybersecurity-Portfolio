# Lateral Movement Investigation - WinRM

## Objective
Detect and investigate potential lateral movement activity by identifying suspicious Windows Remote Management (WinRM) connections between internal systems.

## Incident Scenario
A workstation was compromised after a phishing attack. The attacker used stolen administrator credentials to execute commands remotely through WinRM and expand access within the environment.

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder
- Sysmon

## Data Sources / Log Sources
The investigation uses:
- Windows Security Logs
- Sysmon Logs
- PowerShell Logs
- WinRM Operational Logs

Important Event IDs:

- 4624 - Successful Logon
- 4625 - Failed Logon
- 4688 - Process Creation
- 4104 - PowerShell Script Execution

## MITRE ATT&CK Mapping

- T1021 - Remote Services

Sub-techniques:

- T1021.006 - Windows Remote Management

## Detection Logic

Trigger an alert when:

- WinRM remote sessions are created
- Administrative accounts execute remote commands
- PowerShell execution occurs through WinRM
- Multiple remote executions occur from an unusual host

## Detection Rules

### Sigma Rule

Sigma rule:

[WinRM.sigma.yml](WinRM.sigma.yml)

## Query

### SPL (Splunk)

Query:

[WinRM.spl](WinRM.spl)

## Investigation Steps

1. Identify the source host.
2. Identify the destination host.
3. Review the account used.
4. Analyze executed commands.
5. Verify whether the activity was authorized.

## Timeline

10:00 - Initial workstation compromise  
10:08 - WinRM connection detected  
10:12 - Remote command execution observed  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious WinRM activity from a compromised workstation using privileged credentials, indicating possible lateral movement.

## False Positives

- System administrators
- Remote management tools
- Authorized automation tasks

## Response / Mitigation

- Isolate compromised host
- Reset compromised credentials
- Restrict WinRM access
- Monitor privileged accounts

## Lessons Learned

- Limit remote management exposure
- Monitor privileged remote execution
- Apply least privilege principles
- Segment internal networks

## Detection Validation

Sample log file:

[WinRM.json](WinRM.json)

## Test Case

- WinRM remote session detected
- Privileged account usage
- Remote command execution
- Internal host communication

## Expected Result

SIEM should generate a lateral movement alert when suspicious WinRM activity is detected.
