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

```spl
```

## Detection Logic

## Expected Results

## False Positives

## Recommendations

## References
