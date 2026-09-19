# Timeline — Sentinel Lab 14

## Incident Timeline

**Affected user:** `user1@contoso.com`  
**Date:** September 19, 2026  
**Time zone:** UTC

| Time (UTC) | User | Event | Source | Interval from Previous Event |
|---|---|---|---|---:|
| 08:15:00 | `user1@contoso.com` | Phishing URL clicked | Email | — |
| 08:17:00 | `user1@contoso.com` | Credentials submitted to phishing site | Web | 2 min |
| 08:21:00 | `user1@contoso.com` | Authentication failure | Identity | 4 min |
| 08:22:00 | `user1@contoso.com` | Authentication failure | Identity | 1 min |
| 08:23:00 | `user1@contoso.com` | Authentication failure | Identity | 1 min |
| 08:25:00 | `user1@contoso.com` | Successful authentication | Identity | 2 min |
| 08:29:00 | `user1@contoso.com` | Mailbox accessed | Cloud | 4 min |
| 08:31:00 | `user1@contoso.com` | Mailbox forwarding rule created | Cloud | 2 min |
| 08:34:00 | `user1@contoso.com` | Finance files accessed | Cloud | 3 min |

## Timeline Interpretation

### Phase 1 — Phishing

**08:15 UTC** — The affected user clicks a phishing URL delivered through email.

### Phase 2 — Credential Exposure

**08:17 UTC** — Credentials are submitted to the simulated phishing site two minutes after the phishing interaction.

### Phase 3 — Authentication Activity

**08:21–08:23 UTC** — Three authentication failures occur at one-minute intervals.

**08:25 UTC** — A successful authentication occurs two minutes after the final failure.

### Phase 4 — Post-Authentication Activity

**08:29 UTC** — The mailbox is accessed.

**08:31 UTC** — A mailbox forwarding rule is created.

**08:34 UTC** — Finance files are accessed.

## Investigation Sequence

```text
08:15  Phishing URL clicked
   |
   | +2 min
   v
08:17  Credentials submitted to phishing site
   |
   | +4 min
   v
08:21  Authentication failure
   |
   | +1 min
   v
08:22  Authentication failure
   |
   | +1 min
   v
08:23  Authentication failure
   |
   | +2 min
   v
08:25  Successful authentication
   |
   | +4 min
   v
08:29  Mailbox accessed
   |
   | +2 min
   v
08:31  Mailbox forwarding rule created
   |
   | +3 min
   v
08:34  Finance files accessed
```

## Timeline Query

```kusto
Lab14Events
| where User == "user1@contoso.com"
| sort by TimeGenerated asc
| serialize
| extend PreviousTime = prev(TimeGenerated)
| extend IntervalMinutes = datetime_diff("minute", TimeGenerated, PreviousTime)
| project TimeGenerated, User, Event, Source, PreviousTime, IntervalMinutes
```

## Timeline Summary

The observed sequence progresses from phishing interaction to credential submission, repeated authentication failures, successful authentication, and subsequent cloud activity. All events are associated with the same synthetic account and occur within a 19-minute investigation window.
