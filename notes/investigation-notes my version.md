# Investigation Notes

## Affected Account

- **User:** `user1@contoso.com`
- **Investigation date:** September 19, 2026
- **Time basis:** UTC
- **Telemetry type:** Synthetic KQL `datatable()` events

## Evidence Sources

| Source | Observed activity |
|---|---|
| Email | Phishing URL clicked |
| Web | Credentials submitted to phishing site |
| Identity | Three authentication failures and one successful authentication |
| Cloud | Mailbox access, forwarding-rule creation, and finance-file access |

## Chronological Evidence

### 08:15 UTC — Phishing URL clicked

The first observed event is a phishing URL click associated with `user1@contoso.com`.

**Source:** Email

**Interpretation:** This establishes the initial simulated phishing interaction. By itself, it does not prove that the account was compromised.

### 08:17 UTC — Credentials submitted

Two minutes after the phishing interaction, the dataset records a credential submission to the simulated phishing site.

**Source:** Web

**Interpretation:** This provides evidence that credentials were entered into the phishing flow and gives context for the authentication activity that follows.

### 08:21–08:23 UTC — Authentication failures

Three authentication failures occur at one-minute intervals.

**Source:** Identity

The aggregation query produced:

```text
FailureCount: 3
FirstFailure: 2026-09-19 08:21:00 UTC
LastFailure: 2026-09-19 08:23:00 UTC
```

**Interpretation:** Repeated failures shortly after credential submission represent suspicious authentication activity and justify continued investigation.

### 08:25 UTC — Successful authentication

A successful authentication occurs two minutes after the final failure.

**Source:** Identity

**Interpretation:** The combination of three failures followed by a success is more significant than a successful authentication considered in isolation.

### 08:29 UTC — Mailbox accessed

Four minutes after the successful authentication, the account accesses a mailbox.

**Source:** Cloud

**Interpretation:** This is the first observed post-authentication cloud activity in the dataset.

### 08:31 UTC — Forwarding rule created

A mailbox forwarding rule is created two minutes later.

**Source:** Cloud

**Interpretation:** The event represents account-level mailbox manipulation in the simulated scenario and provides an additional post-authentication indicator.

### 08:34 UTC — Finance files accessed

Three minutes after the forwarding-rule event, finance files are accessed.

**Source:** Cloud

**Interpretation:** This extends the observed post-authentication activity beyond the mailbox and into sensitive file access.

## Correlation Analysis

The evidence can be organized into the following sequence:

```text
08:15  Phishing URL clicked
   ↓ 2 min
08:17  Credentials submitted to phishing site
   ↓ 4 min
08:21  Authentication failure
   ↓ 1 min
08:22  Authentication failure
   ↓ 1 min
08:23  Authentication failure
   ↓ 2 min
08:25  Successful authentication
   ↓ 4 min
08:29  Mailbox accessed
   ↓ 2 min
08:31  Mailbox forwarding rule created
   ↓ 3 min
08:34  Finance files accessed
```

The sequence contains three useful correlation dimensions:

1. **Same user:** all events are associated with `user1@contoso.com`.
2. **Temporal relationship:** each stage follows the previous stage within the same investigation window.
3. **Activity progression:** the observed behavior moves from phishing to credential submission, authentication, and post-authentication cloud activity.

