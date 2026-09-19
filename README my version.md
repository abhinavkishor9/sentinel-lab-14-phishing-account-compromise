# Sentinel Lab 14 — Phishing → Account Compromise

## Overview

This lab simulates a phishing-driven account compromise in Microsoft Sentinel using KQL datatable(). Instead of relying on live Microsoft Entra ID, Defender, or mailbox telemetry, the lab creates a controlled synthetic event stream that represents different stages of an attack.

The investigation follows the activity chronologically:

Phishing Email
      ↓
Credential Submission
      ↓
Multiple Authentication Failures
      ↓
Successful Authentication
      ↓
Mailbox Access
      ↓
Mailbox Rule Creation
      ↓
Sensitive File Access

The main objective is to practice event correlation and investigation, not simply identify a suspicious login.

A single Lab14Events datatable() is used as the foundation of the lab. Additional fields can be introduced later as the investigation becomes more detailed.

Investigation principle

An individual event is an indicator; the correlated sequence provides the investigation context.

For example, a phishing click by itself does not prove account compromise. A stronger investigation develops when that event is followed by credential submission, authentication activity, successful access, and post-authentication actions involving the same account.

This lab simulates a phishing-driven account compromise investigation in Microsoft Sentinel using KQL `datatable()` data.

The lab follows a single user, `user1@contoso.com`, through a sequence of events that begins with a phishing URL click and progresses to credential submission, repeated authentication failures, successful authentication, mailbox access, mailbox rule creation, and finance file access.

The purpose of the lab is to practice evidence-driven correlation across event type, affected user, source, and event timing.

> **Investigation principle:** Follow the evidence and the sequence of events rather than treating one indicator as proof of compromise.

## Scenario

A SOC analyst receives an alert concerning suspicious activity involving the Microsoft 365 account `user1@contoso.com`. The investigation begins with evidence that the user interacted with a phishing URL delivered through email.

Shortly afterward, the available telemetry records a credential submission to the simulated phishing site. Within the next few minutes, the same account generates multiple authentication failures followed by a successful authentication.

The investigation is expanded to determine what occurred after the successful login. Additional cloud activity shows mailbox access, creation of a mailbox forwarding rule, and access to finance files.

The analyst must determine whether these events represent a connected sequence of suspicious activity rather than unrelated events. The investigation focuses on the relationship between the phishing interaction and credential submission, the repeated authentication failures preceding the successful authentication, the timing between authentication activity and subsequent cloud actions, and the progression from account access to mailbox and sensitive file activity.

The lab uses a synthetic `Lab14Events` dataset created with KQL `datatable()`. The dataset contains:

- Email activity representing the phishing URL interaction.
- Web activity representing credential submission to the simulated phishing site.
- Identity activity representing authentication failures and successful authentication.
- Cloud activity representing mailbox access, mailbox forwarding-rule creation, and finance-file access.

All events are associated with `user1@contoso.com` and are represented within the same UTC investigation window.

The analyst should reconstruct the incident chronologically, identify meaningful relationships between the events, and determine how the evidence develops across each stage of the investigation.

The investigation should not treat the initial phishing event or successful authentication as standalone proof of account compromise. Instead, the analyst should evaluate the complete sequence and document which observations are directly supported by the available synthetic telemetry.

```text
Phishing interaction
        ↓
Credential submission
        ↓
Authentication failures
        ↓
Successful authentication
        ↓
Mailbox activity
        ↓
Mailbox rule modification
        ↓
Finance file access
````

The final investigation should provide a clear timeline, summarize the observed activity for the affected account, and record the limitations of the synthetic telemetry used in the lab.

```
```

## Lab Objectives

```markdown

- Simulate a phishing-driven account compromise investigation in Microsoft Sentinel using KQL `datatable()`.
- Trace the progression from a phishing URL click to credential submission, authentication activity, and post-authentication cloud activity.
- Analyze repeated authentication failures and identify a subsequent successful authentication associated with the same user.
- Use chronological event ordering to reconstruct the sequence of activity during the simulated incident.
- Calculate time intervals between related events to identify the temporal relationships within the attack sequence.
- Use KQL filtering to isolate events by user, event type, and simulated telemetry source.
- Use `summarize` and `countif()` to build an activity profile for the affected account.
- Correlate Email, Web, Identity, and Cloud events using the affected user and event timing as investigation pivots.
- Examine post-authentication mailbox and file activity to determine how the investigation develops beyond the initial phishing event.
- Distinguish individual indicators from conclusions supported by multiple correlated events.
- Document confirmed observations and telemetry limitations without assuming unavailable production security data.
- Practice an evidence-driven SOC investigation workflow using a controlled and reproducible synthetic dataset.
```

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

