پيشنهاد جديد:
# Lateral Movement Investigation

## Objective
Detect and investigate potential lateral movement activity by identifying suspicious Remote Desktop Protocol (RDP) connections between internal systems.

---

## Incident Scenario
A workstation was compromised following a phishing attack. The attacker obtained privileged credentials and used Remote Desktop Protocol (RDP) to access multiple internal servers, attempting to expand control within the environment.

---

## Environment
- Windows Server 2022
- Windows Security Logs
- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon

---

## ATT&CK Mapping

**Technique**
- T1021 – Remote Services

**Sub-technique**
- T1021.001 – Remote Desktop Protocol (RDP)

---

## ATT&CK Data Sources

- Logon Session
- Authentication Logs
- Network Traffic
- Process Creation (Sysmon)

---

## Log Sources

- Windows Security Logs
- Terminal Services Logs
- Sysmon Logs
- Firewall Logs

### Important Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Logon with Explicit Credentials |
| 4778 | RDP Session Reconnected |
| 4779 | RDP Session Disconnected |

---

## Detection Logic

Generate an alert when one or more of the following conditions are observed:

- Successful RDP logon (Logon Type 10)
- Multiple RDP sessions within a short time window
- Connections originating from an unusual internal host
- Privileged account authentication from unexpected systems

---

## Detection Rules

### Sigma

```
RDP.sigma.yml
```

### Splunk (SPL)

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| bucket span=10m _time
| stats count values(Account_Name) as usernames values(WorkstationName) as SourceHost by ComputerName _time
| where count >= 3
```

```
RDP.spl
```

### Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| summarize LogonCount=count(), Hosts=make_set(Computer)
by Account, IpAddress, bin(TimeGenerated, 10m)
| where LogonCount >= 3
```

---

## Investigation Steps

1. Identify the source host.
2. Identify the destination host(s).
3. Review the account used for authentication.
4. Verify whether the activity was authorized.
5. Correlate with previous authentication events.
6. Review Sysmon Process Creation events.
7. Check for PowerShell execution or suspicious services.
8. Determine whether additional lateral movement occurred.

---

## Indicators of Compromise (IOCs)

- Multiple RDP logons within a short period
- Administrative account used across multiple hosts
- Authentication from an unusual workstation
- Access to multiple internal systems

---

## Timeline

| Time | Activity |
|------|----------|
| 10:00 | Initial workstation compromise |
| 10:08 | First RDP connection detected |
| 10:12 | Multiple RDP sessions observed |
| 10:15 | SIEM alert generated |

---

## Findings

The investigation identified multiple successful RDP logons from a compromised workstation to several internal servers using a privileged account, indicating potential lateral movement.

---

## False Positives

- System administrators
- Helpdesk remote support
- Authorized maintenance activities
- Automated administration tools

---

## Severity

| Level | Condition |
|-------|-----------|
| Medium | Single suspicious RDP session |
| High | Multiple RDP sessions across hosts |
| Critical | Privileged account performing lateral movement |

---

## Response / Mitigation

- Isolate the compromised workstation
- Reset compromised credentials
- Restrict RDP access
- Review privileged account activity
- Enable Multi-Factor Authentication (MFA)
- Review firewall and segmentation policies

---

## Detection Validation

### Test Data

The detection was validated using simulated Windows Security Event 4624 logs.

```
RDP.json
```

### Test Case

- Successful RDP logon
- Logon Type 10
- Administrative account
- Multiple destination hosts
- Detection window: 10 minutes

---

## Detection Improvements

Future
