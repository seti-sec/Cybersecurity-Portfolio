# Lateral Movement Investigation - Pass-the-Hash

## Objective

Detect and investigate potential lateral movement activity by identifying suspicious NTLM authentication patterns associated with Pass-the-Hash attacks.

## Incident Scenario

A workstation was compromised after a phishing attack. The attacker extracted authentication material and used stolen NTLM hashes to authenticate to internal systems without knowing the original password.

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
- Authentication Logs
- Domain Controller Logs

Important Event IDs:

- 4624 - Successful Logon
- 4625 - Failed Logon
- 4648 - Logon with Explicit Credentials
- 4672 - Special Privileges Assigned

## MITRE ATT&CK Mapping

- T1550 - Use Alternate Authentication Material

Sub-techniques:

- T1550.002 - Pass the Hash

## Detection Logic

Trigger an alert when:

- NTLM authentication occurs from unusual hosts
- Privileged accounts authenticate from unexpected systems
- Multiple systems are accessed using the same account
- Suspicious authentication patterns are detected

## Detection Rules

### Sigma Rule

[Pass-the-Hash.sigma.yml](./Pass-the-Hash.sigma.yml)

## Query

### SPL (Splunk)

[Pass-the-Hash.spl](Pass-the-Hash.spl)

## Investigation Steps

1. Identify the source host.
2. Identify the destination systems.
3. Review the account used.
4. Analyze NTLM authentication activity.
5. Verify whether the authentication was authorized.

## Timeline

10:00 - Initial workstation compromise  
10:08 - NTLM authentication detected  
10:12 - Multiple internal systems accessed  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious NTLM authentication activity using privileged credentials, indicating possible Pass-the-Hash lateral movement.

## False Positives

- Legacy applications
- Domain administration
- Authorized remote management

## Response / Mitigation

- Isolate compromised systems
- Reset compromised credentials
- Reduce NTLM usage
- Monitor privileged authentication

## Lessons Learned

- Limit NTLM authentication
- Protect privileged accounts
- Monitor abnormal authentication patterns
- Implement stronger authentication controls

## Detection Validation

Sample log file:

[Pass-the-Hash.json](Pass-the-Hash.json)

## Test Case

- NTLM authentication detected
- Privileged account usage
- Multiple internal hosts
- Suspicious lateral movement pattern

## Expected Result

SIEM should generate a lateral movement alert when suspicious Pass-the-Hash activity is detected.
