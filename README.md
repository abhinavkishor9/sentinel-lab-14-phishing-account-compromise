# Sentinel Lab 14 — Phishing → Account Compromise

## Overview

This lab simulates a phishing-driven account compromise investigation in Microsoft Sentinel using KQL `datatable()` data.

The lab follows a single user, `user1@contoso.com`, through a sequence of events that begins with a phishing URL click and progresses to credential submission, repeated authentication failures, successful authentication, mailbox access, mailbox rule creation, and finance file access.

The purpose of the lab is to practice evidence-driven correlation across event type, affected user, source, and event timing.

> **Investigation principle:** Follow the evidence and the sequence of events rather than treating one indicator as proof of compromise.

## Scenario

A simulated phishing message is followed by credential submission from the affected user. Shortly afterward, the same account generates three authentication failures and then a successful authentication. Additional cloud activity occurs after the successful authentication, including mailbox access, creation of a mailbox forwarding rule, and access to finance files.

The investigation uses synthetic telemetry rather than live Entra ID, Defender, or mailbox data. The dataset is intentionally small so each event can be traced and correlated during the investigation.

## Lab Objectives

- Build and query a reproducible Sentinel dataset with KQL `datatable()`.
- Establish a chronological incident timeline for a single affected user.
- Identify phishing and credential-submission activity.
- Measure repeated authentication failures and subsequent successful authentication.
- Investigate activity occurring after successful authentication.
- Use time-based correlation to connect separate stages of the simulated incident.
- Distinguish individual indicators from stronger conclusions supported by multiple correlated events.

## Lab Environment

- Microsoft Sentinel
- Microsoft Sentinel Logs / KQL Query Editor
- Kusto Query Language (KQL)
- Synthetic telemetry created with `datatable()`

## Synthetic Dataset

The lab uses one logical table named `Lab14Events` with the following fields:

| Field | Description |
|---|---|
| `TimeGenerated` | Event timestamp in UTC |
| `User` | Affected account |
| `Event` | Simulated activity |
| `Source` | Simulated telemetry source |

The investigation contains nine chronological events for `user1@contoso.com`.

## Incident Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 08:15 | Phishing URL clicked | Email |
| 08:17 | Credentials submitted to phishing site | Web |
| 08:21 | Authentication failure | Identity |
| 08:22 | Authentication failure | Identity |
| 08:23 | Authentication failure | Identity |
| 08:25 | Successful authentication | Identity |
| 08:29 | Mailbox accessed | Cloud |
| 08:31 | Mailbox forwarding rule created | Cloud |
| 08:34 | Finance files accessed | Cloud |

## Investigation Workflow

### 1. Review the complete event stream

```kusto
Lab14Events
| where User == "user1@contoso.com"
| project TimeGenerated, User, Event, Source
| order by TimeGenerated asc
```

### 2. Identify the phishing event

```kusto
Lab14Events
| where Source == "Email"
| order by TimeGenerated asc
```

### 3. Identify credential submission

```kusto
Lab14Events
| where Event == "Credentials submitted to phishing site"
| project TimeGenerated, User, Event, Source
```

### 4. Review authentication failures

```kusto
Lab14Events
| where Source == "Identity"
| where Event == "Authentication failure"
| summarize
    FailureCount = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by User
```

### 5. Identify successful authentication

```kusto
Lab14Events
| where Event == "Successful authentication"
| project TimeGenerated, User, Event, Source
```

### 6. Correlate failures with success

```kusto
Lab14Events
| where Source == "Identity"
| summarize
    FailureCount = countif(Event == "Authentication failure"),
    SuccessCount = countif(Event == "Successful authentication"),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
    by User
| where FailureCount >= 3 and SuccessCount >= 1
```

### 7. Review post-authentication cloud activity

```kusto
Lab14Events
| where Source == "Cloud"
| order by TimeGenerated asc
```

### 8. Calculate event-to-event intervals

For `prev()` analysis, sort the event stream before calculating the previous timestamp.

```kusto
Lab14Events
| where User == "user1@contoso.com"
| sort by TimeGenerated asc
| serialize
| extend PreviousTime = prev(TimeGenerated)
| extend IntervalMinutes = datetime_diff("minute", TimeGenerated, PreviousTime)
| project TimeGenerated, Event, Source, PreviousTime, IntervalMinutes
```

### 9. Create an account activity summary

```kusto
Lab14Events
| summarize
    PhishingEvents = countif(Event == "Phishing URL clicked"),
    CredentialEvents = countif(Event == "Credentials submitted to phishing site"),
    AuthenticationFailures = countif(Event == "Authentication failure"),
    SuccessfulLogins = countif(Event == "Successful authentication"),
    MailboxAccess = countif(Event == "Mailbox accessed"),
    ForwardingRules = countif(Event == "Mailbox forwarding rule created"),
    FileAccess = countif(Event == "Finance files accessed")
    by User
```

## Findings

The investigation produced the following evidence for `user1@contoso.com`:

- One phishing URL click at 08:15 UTC.
- One credential-submission event at 08:17 UTC.
- Three authentication failures from 08:21 to 08:23 UTC.
- One successful authentication at 08:25 UTC.
- One mailbox access event at 08:29 UTC.
- One mailbox forwarding-rule creation event at 08:31 UTC.
- One finance-file access event at 08:34 UTC.

The observed timing was:

| Sequence | Interval |
|---|---:|
| Phishing URL click → Credential submission | 2 minutes |
| Credential submission → First authentication attempt | 4 minutes |
| Authentication failure → Next failure | 1 minute |
| Authentication failure → Next failure | 1 minute |
| Last authentication failure → Successful authentication | 2 minutes |
| Successful authentication → Mailbox access | 4 minutes |
| Mailbox access → Forwarding rule creation | 2 minutes |
| Forwarding rule creation → Finance file access | 3 minutes |

The evidence forms a coherent simulated phishing-to-account-compromise sequence. The lab does not rely on the phishing event alone; the conclusion is supported by the subsequent authentication and cloud activity occurring for the same account in a closely connected time sequence.

## MITRE ATT&CK Mapping

The scenario can be mapped to the following ATT&CK techniques based on the simulated behaviors:

| Technique | ID | Lab evidence |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Phishing URL clicked |
| Valid Accounts | T1078 | Successful authentication using the affected account |
| Email Account Manipulation | T1098.002 | Mailbox forwarding rule created |

These mappings describe the simulated behavior represented in the lab and are not claims about a real-world intrusion.

## Limitations

This lab uses synthetic data created with KQL `datatable()` and therefore does not demonstrate the fields, schemas, enrichment, or alerting behavior of live Microsoft security products.

The dataset also does not contain source IP, device, user-agent, geographic, conditional-access, MFA, or raw mailbox audit fields. Those limitations should be considered when interpreting the investigation.

## Conclusion

The lab demonstrates how a SOC analyst can move from an initial phishing indicator to a broader account-compromise investigation by correlating events across time and activity type. The sequence from phishing interaction through credential submission, authentication activity, and post-authentication cloud actions provides the main investigative evidence.
