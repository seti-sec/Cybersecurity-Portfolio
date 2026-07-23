# Phishing Investigation

## Objective
Detect and investigate phishing attacks by analyzing suspicious emails, malicious links, attachments, sender information, and user activity.
## Incident Scenario
A user receives an email that appears to be from the company's IT department. The email asks the user to verify their account by clicking a link.
The link redirects the user to a fake login page designed to steal credentials.
The SOC team investigates the email, sender domain, URL reputation, and user activity to determine whether the message is part of a phishing campaign.
## Environment
- Email Security Gateway
- Microsoft 365 / Exchange Logs
- SIEM (Splunk)
- Endpoint Logs
## Data Sources / Log Sources
The investigation uses the following data sources:
- Email Gateway Logs
- Microsoft 365 / Exchange Audit Logs
- URL Reputation Logs
- Proxy Logs
- DNS Logs
- Endpoint Detection Logs
  
Important data points:
- Sender email address
- Sender domain
- Recipient user
- Email subject
- URL/domain
- Attachment information
- User click activity
## MITRE ATT&CK Mapping
T1566 - Phishing
Sub-techniques:
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
## Detection Logic
Generate an alert when:
- Email contains suspicious URLs
- Sender domain is newly registered or suspicious
- Attachment contains potentially malicious file types
- Multiple users receive the same suspicious email
- User clicks a suspicious link
  
Correlation examples:
- Email delivery
- User click event
- Authentication activity after click
## Query

### SPL (Splunk)
The SPL detection rule is available here:
[phishing_detection.spl](queries/phishing_detection.spl)
### KQL (Microsoft Sentinel)
```kql
EmailEvents
| where Subject contains "verify"
   or Subject contains "password"
| where SenderFromDomain !endswith "company.com"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject

## Investigation Steps
1. Analyze the suspicious email headers.
2. Verify sender domain reputation.
3. Extract and analyze URLs from the email.
4. Check if the user clicked the suspicious link.
5. Review authentication logs after the click.
6. Determine whether credentials were compromised.
## Timeline
| Time | Event |
|---|---|
| 09:30 | Suspicious phishing email received |
| 09:35 | User clicked malicious URL |
| 09:40 | SOC started investigation |

## Findings
- Email originated from a suspicious domain.
- URL was designed to harvest user credentials.
- User interaction with the malicious link was detected.
- No confirmed malware execution was observed.

## False Positives
Possible false positives:
- Legitimate security awareness training emails.
- Internal emails containing verification links.
- Newly registered company domains.

## Response / Mitigation
- Block malicious sender domain.
- Block malicious URL.
- Reset compromised user credentials.
- Investigate affected users.
- Add indicators to security tools.

## Lessons Learned
- User awareness is critical against phishing attacks.
- Email filtering rules should be continuously improved.
- Detection rules must correlate email and user activity.

## References

## Detection Validation
