# Credential Access Investigation - Kerberoasting

## Objective

Detect and investigate potential credential access activity by identifying suspicious Kerberos service ticket requests.

## Incident Scenario

A compromised workstation was used by an attacker to request service tickets for domain accounts in order to extract and crack service account credentials.

## Environment

- Windows Server 2022
- Active Directory
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Domain Controller Security Logs
- Windows Security Logs
- Kerberos Authentication Logs

Important Event IDs:

- 4769 - Kerberos Service Ticket Requested
- 4624 - Successful Logon
- 4672 - Special Privileges Assigned

## MITRE ATT&CK Mapping

- T1558 - Steal or Forge Kerberos Tickets

Sub-techniques:

- T1558.003 - Kerberoasting

## Detection Logic

Trigger an alert when:

- Multiple service tickets are requested
- RC4 encrypted Kerberos tickets are requested
- A user requests tickets for unusual service accounts
- High volume Kerberos activity occurs in a short period

## Detection Rules

### Sigma Rule

Kerberoasting.sigma.yml

## Query

### SPL (Splunk)

Kerberoasting.spl

## Investigation Steps

1. Identify the requesting user.
2. Identify targeted service accounts.
3. Review Kerberos ticket activity.
4. Check account privileges.
5. Verify whether activity is authorized.

## Timeline

10:00 - Initial compromise  
10:08 - Kerberos ticket requests detected  
10:12 - Multiple service accounts targeted  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious Kerberos service ticket requests, indicating possible Kerberoasting activity.

## False Positives

- Normal domain authentication
- Legacy applications
- Service account operations

## Response / Mitigation

- Reset compromised service account passwords
- Disable weak encryption types
- Monitor privileged accounts
- Review Active Directory activity

## Lessons Learned

- Use strong service account passwords
- Monitor Kerberos activity
- Reduce unnecessary privileges
- Protect service accounts

## Detection Validation

Sample log file:

Kerberoasting.json

## Test Case

- Event ID 4769 detected
- RC4 ticket encryption
- Multiple service ticket requests
- Suspicious account activity

## Expected Result

SIEM should generate an alert when suspicious Kerberoasting activity is detected.
