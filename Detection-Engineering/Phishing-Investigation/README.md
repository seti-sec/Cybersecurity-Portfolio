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

### KQL (Microsoft Sentinel)

## Investigation Steps

## Timeline

## Findings

## False Positives

## Response / Mitigation

## Lessons Learned

## References

## Detection Validation
