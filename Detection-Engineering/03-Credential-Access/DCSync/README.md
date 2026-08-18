# Credential Access Investigation - DCSync

## Objective

Detect and investigate potential credential access activity by identifying suspicious Active Directory replication requests.

## Incident Scenario

A compromised account with elevated privileges was used by an attacker to request directory replication data from a domain controller in order to obtain password hashes and authentication material.

## Environment

- Windows Server 2022
- Active Directory Domain Services
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Domain Controller Security Logs
- Windows Security Logs
- Active Directory Audit Logs

Important Event IDs:

- 4662 - Directory Service Object Access
- 4624 - Successful Logon
- 4672 - Special Privileges Assigned

## MITRE ATT&CK Mapping

- T1003 - OS Credential Dumping

Sub-techniques:

- T1003.006 - DCSync

## Detection Logic

Trigger an alert when:

- A non-domain controller requests replication permissions
- Directory replication rights are used unexpectedly
- Privileged accounts perform unusual replication activity

## Detection Rules

### Sigma Rule

[DCSync.sigma.yml](DCSync.sigma.yml)

## Query

### SPL (Splunk)

[DCSync.spl](DCSync.spl)

## Investigation Steps

1. Identify the account requesting replication.
2. Identify the source computer.
3. Verify domain controller activity.
4. Review account privileges.
5. Check for credential theft indicators.

## Timeline

10:00 - Initial compromise  
10:08 - Directory replication request detected  
10:12 - Privileged account activity observed  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious Active Directory replication activity, indicating possible DCSync credential theft.

## False Positives

- Domain controllers
- Authorized replication
- Directory management tools

## Response / Mitigation

- Disable compromised accounts
- Reset privileged credentials
- Review replication permissions
- Monitor domain administrator activity

## Lessons Learned

- Protect privileged accounts
- Audit replication permissions
- Monitor Active Directory changes
- Apply least privilege principles

## Detection Validation

Sample log file:

[DCSync.json](DCSync.json)

## Test Case

- Event ID 4662 detected
- Replication access requested
- Privileged account involved

## Expected Result

SIEM should generate an alert when suspicious DCSync activity is detected.
