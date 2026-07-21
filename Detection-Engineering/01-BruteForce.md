# Brute Force Detection

## Objective

Detect potential brute force attacks by identifying multiple failed authentication attempts from the same source within a defined time window.

## Attack Scenario

An attacker attempts to guess a user's password by repeatedly trying different password combinations. This behavior generates multiple failed logon events that can be detected in Splunk.

## Log Source

- Windows Security Logs
- Event ID: 4625 (Failed Logon)

## MITRE ATT&CK

- T1110 – Brute Force

## SPL Query

**Brute Force Detection for alert:
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by _time, Account_Name , Source_Network_Address
| where count >= 10
| sort -count

## Detection Logic
Detect multiple Windows failed logon events (Event ID 4625) from the same source IP or targeting the same account within a short period, indicating a possible brute-force attack.
## Expected Results
 Source IP
 Username
 Hostname
 Number of failed logons 
 Time window
## False Positives
 Users entering incorrect passwords repeatedly
 Password expiration events
 Service accounts with outdated credentials
 Vulnerability scanners or security assessment tools
## Recommendations
Investigate the source IP. Check for successful logons (Event ID 4624) after the failed attempts.
 Lock or monitor the affected account. Enable MFA.
 Block malicious IPs if confirmed.
## References

