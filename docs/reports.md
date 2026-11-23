# Scheduled CVE reports

Reports send a daily or weekly overview through your existing Telegram, Discord
or Slack connectors. The monitoring worker schedules them and the persistent
delivery queue handles spacing, connector delivery hours, retries and history.
They are separate from immediate alert rules: enabling a report does not disable
your existing immediate alerts.

In **Reports → Add report**, choose:

- **Worldwide** for recently published records in the local NVD database.
- **My assets** for recently published records matching your currently enabled
  assets and notification rules. A matching rule still needs a configured
  destination; reports can go to any connector you choose. The report shows one
  matching asset, rule and confidence for each included CVE; other matches may
  exist and a potential match does not confirm the installed version is affected.

Set the daily/weekly schedule, IANA timezone, minimum CVSS, maximum entries and
at least one destination. A minimum of zero includes unknown CVSS; a higher
threshold excludes unscored records. Save and use **Preview** to inspect a
report without sending. A saved report first runs at its next scheduled time;
editing it recalculates that time. The period ends at the scheduled occurrence,
not when a delayed message is delivered. Empty periods generate an explicit
zero-entry report. Reports do not currently use AI summaries.

These reports cover **only locally synchronized NVD records that have a
publication date**, with enrichment where available. They cannot promise a
complete worldwide list. Each message includes the last successful NVD sync,
the number of locally eligible records, how many were examined and an
incompleteness warning. Records are considered newest first; at most 1,000
candidates are examined per report and the message may contain fewer than the
configured maximum because of provider length limits. Scores or matches can be
unknown. CVEs discovered after the source synchronization window, records without
NVD publication dates, and records unavailable during an outage may be absent.

Report schedules and queue identities survive restarts. If the monitor was
offline through several occurrences, only the latest completed period is queued;
older missed periods are not replayed. The same report occurrence and
destination are not queued twice, although a crash after provider acceptance can
still result in a repeated delivery. Before sending, disabled/deleted reports or
removed destinations are cancelled, and matches are re-evaluated with current
rules. Normal connector hours apply, so the final delivery can be later than the
report schedule. DST gaps move the time to the first valid local minute; repeated
local times run once at the first occurrence.

For headless setup, edit [the example](../examples/weekly-report.json) with a
connector ID obtained from `vulnrelay connectors list`, then:

```sh
vulnrelay reports add weekly-report.json
vulnrelay reports list
vulnrelay reports preview REPORT_ID
vulnrelay reports update REPORT_ID weekly-report.json
vulnrelay reports delete REPORT_ID
```

No external service is contacted by the preview command. To send on schedule,
keep the monitor running. Real Telegram/Discord/Slack delivery should be checked
by the operator; tests use synthetic data and mocked providers.
