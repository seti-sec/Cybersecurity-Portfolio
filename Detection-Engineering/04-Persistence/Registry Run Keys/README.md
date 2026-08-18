# Persistence Investigation - Registry Run Keys

## Objective

Detect and investigate persistence activity by identifying suspicious modifications to Windows Registry Run Keys.

## Incident Scenario

A compromised workstation was modified by an attacker who added malicious entries to Registry Run Keys to execute malware automatically when a user logs in.

## Environment

- Windows Server 2022
- Sysmon
- Windows Registry Logs
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Sysmon Registry Events
- Windows Security Logs
- Endpoint Detection Logs

Important Event IDs:

- Sysmon Event ID 13 - Registry Value Set

## MITRE ATT&CK Mapping

- T1547 - Boot or Logon Autostart Execution

Sub-techniques:

- T1547.001 - Registry Run Keys / Startup Folder

## Detection Logic

Trigger an alert when:

- Registry Run Keys are modified
- Unknown processes create startup entries
- Suspicious executables are configured for automatic execution

## Detection Rules

### Sigma Rule

[Registry Run Keys.sigma.yml](Registry Run Keys.sigma.yml)

## Query

### SPL (Splunk)

[Registry Run Keys.spl](Registry Run Keys.spl)

## Investigation Steps

1. Identify modified registry keys.
2. Review the executable path.
3. Identify the modifying process.
4. Analyze file reputation.
5. Verify whether the change was authorized.

## Timeline

10:00 - Initial compromise  
10:08 - Registry modification detected  
10:12 - Persistence mechanism identified  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious Registry Run Key modifications, indicating possible persistence activity.

## False Positives

- Software installations
- Enterprise management tools
- System updates

## Response / Mitigation

- Remove malicious registry entries
- Delete associated malware
- Reset compromised credentials
- Review startup locations

## Lessons Learned

- Monitor registry persistence locations
- Restrict unauthorized software execution
- Audit endpoint changes

## Detection Validation

Sample log file:

[Registry Run Keys.json](Registry Run Keys.json)

## Test Case

- Registry Run Key modification detected
- Unknown process involved
- Suspicious executable path

## Expected Result

SIEM should generate an alert when suspicious Registry Run Key persistence is detected.
