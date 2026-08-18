# Persistence Investigation - WMI Event Subscription

## Objective

Detect and investigate persistence activity by identifying suspicious Windows Management Instrumentation (WMI) event subscriptions.

## Incident Scenario

A compromised system was modified by an attacker who created a WMI event subscription to execute malicious code automatically when specific system events occur.

## Environment

- Windows Server 2022
- Sysmon
- Windows Security Logs
- Splunk Enterprise
- Universal Forwarder

## Data Sources / Log Sources

The investigation uses:

- Sysmon WMI Events
- Windows Security Logs
- Endpoint Detection Logs

Important Event IDs:

- Sysmon Event ID 19 - WMI Event Filter Activity
- Sysmon Event ID 20 - WMI Event Consumer Activity
- Sysmon Event ID 21 - WMI Binding Activity

## MITRE ATT&CK Mapping

- T1546 - Event Triggered Execution

Sub-techniques:

- T1546.003 - WMI Event Subscription

## Detection Logic

Trigger an alert when:

- New WMI event subscriptions are created
- Unknown processes create WMI consumers
- Suspicious commands execute through WMI triggers

## Detection Rules

### Sigma Rule

[WMI Event Subscription.sigma.yml](WMI Event Subscription.sigma.yml)

## Query

### SPL (Splunk)

[WMI Event Subscription.spl](WMI Event Subscription.spl)

## Investigation Steps

1. Identify the WMI subscription creator.
2. Review WMI filters and consumers.
3. Analyze executed commands.
4. Identify related processes.
5. Verify whether the subscription is authorized.

## Timeline

10:00 - Initial compromise  
10:08 - WMI subscription created  
10:12 - Persistence mechanism detected  
10:15 - SIEM alert generated  

## Findings

The investigation identified suspicious WMI event subscription activity, indicating possible persistence.

## False Positives

- Management software
- Monitoring systems
- Administrative tools

## Response / Mitigation

- Remove malicious WMI subscriptions
- Investigate related processes
- Isolate compromised hosts
- Review privileged accounts

## Lessons Learned

- Monitor WMI activity
- Restrict unauthorized persistence mechanisms
- Audit endpoint changes

## Detection Validation

Sample log file:

[WMI Event Subscription.json](WMI Event Subscription.json)

## Test Case

- WMI event subscription detected
- Unknown consumer created
- Suspicious execution trigger

## Expected Result

SIEM should generate an alert when suspicious WMI Event Subscription persistence is detected.
