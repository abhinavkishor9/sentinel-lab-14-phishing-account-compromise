# Troubleshooting Notes 

## Issue 1 — Initial multi-table `datatable()` implementation produced a Sentinel query error

### Original approach

The first implementation defined separate `datatable()` objects for phishing, credential capture, authentication, and post-compromise activity, then combined them with `union`.

### Problem encountered

The query continued to produce an error in the Sentinel Logs editor even after changes were made to the datetime syntax.

The exact parser/root-cause message was not captured in the investigation notes, so the specific internal parser cause should not be assumed.

### Resolution

The lab was simplified to one synthetic table named `Lab14Events` with a consistent schema:

```kusto
let Lab14Events = datatable(
    TimeGenerated:datetime,
    User:string,
    Event:string,
    Source:string
)
[
    datetime(2026-09-19T08:15:00), "user1@contoso.com", "Phishing URL clicked", "Email",
    datetime(2026-09-19T08:17:00), "user1@contoso.com", "Credentials submitted to phishing site", "Web",
    datetime(2026-09-19T08:21:00), "user1@contoso.com", "Authentication failure", "Identity",
    datetime(2026-09-19T08:22:00), "user1@contoso.com", "Authentication failure", "Identity",
    datetime(2026-09-19T08:23:00), "user1@contoso.com", "Authentication failure", "Identity",
    datetime(2026-09-19T08:25:00), "user1@contoso.com", "Successful authentication", "Identity",
    datetime(2026-09-19T08:29:00), "user1@contoso.com", "Mailbox accessed", "Cloud",
    datetime(2026-09-19T08:31:00), "user1@contoso.com", "Mailbox forwarding rule created", "Cloud",
    datetime(2026-09-19T08:34:00), "user1@contoso.com", "Finance files accessed", "Cloud"
];

Lab14Events
| order by TimeGenerated asc
```

### Lesson

For a small synthetic Sentinel lab, a single table with a common schema is easier to validate before introducing joins or unions.

---

## Issue 2 — Validate the smallest possible `datatable()` first

### Troubleshooting approach

Instead of debugging the entire investigation query at once, the dataset was reduced to a minimal `datatable()` test containing the same four fields:

```kusto
datatable(
    TimeGenerated:datetime,
    User:string,
    Event:string,
    Source:string
)
[
    datetime(2026-09-19T08:15:00), "user1@contoso.com", "Phishing URL clicked", "Email",
    datetime(2026-09-19T08:17:00), "user1@contoso.com", "Credentials submitted", "Web"
]
| order by TimeGenerated asc
```

Once the simplified dataset approach was validated, the complete nine-event dataset was used for the investigation.

### Lesson

When KQL fails, isolate the parser problem from the investigation logic:

```text
Minimal datatable
      ↓
Add remaining rows
      ↓
Add filters
      ↓
Add summarize
      ↓
Add sequence analysis
```

---

## Issue 3 — `prev()` requires an ordered event stream

### Risk

The sequence-analysis query used `prev(TimeGenerated)` to calculate the interval between events.

Using `prev()` without deliberately establishing the event order can make the previous row ambiguous.

### Safer query

```kusto
Lab14Events
| where User == "user1@contoso.com"
| sort by TimeGenerated asc
| serialize
| extend PreviousTime = prev(TimeGenerated)
| extend IntervalMinutes = datetime_diff("minute", TimeGenerated, PreviousTime)
| project TimeGenerated, Event, Source, PreviousTime, IntervalMinutes
```

### Lesson

For timeline or delta analysis:

```text
Sort chronologically
       ↓
Serialize the row set
       ↓
Use prev()
       ↓
Calculate the interval
```

---

## Issue 4 — Avoid treating a single indicator as a confirmed compromise

### Investigation risk

A phishing click or a successful authentication can each be suspicious without independently proving account takeover.

### Resolution

The investigation was structured around multiple correlated stages:

```text
Phishing
   ↓
Credential submission
   ↓
Authentication failures
   ↓
Successful authentication
   ↓
Post-authentication cloud activity
```

### Lesson

The lab focuses on correlation rather than indicator-only conclusions.

---

