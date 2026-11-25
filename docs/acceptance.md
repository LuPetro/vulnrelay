# Acceptance: a real alert and restart

Use a **separate test instance and private test destination**. Automated tests
mock providers; a successful test message proves credentials and destination
permissions, but it does not prove that a CVE matches your asset or rule. This
checklist is for an operator who controls the test bot and instance. A German
version is available in [Erster Abnahmetest](first-test.md).

Before starting, note the commit with `git rev-parse --short HEAD` and check
`docker compose ps`, `docker compose exec vulnrelay vulnrelay doctor`, and
`docker compose exec monitor vulnrelay engine-health`. The worker heartbeat
alone does not establish that NVD or a destination is healthy. Check source
status and last successful synchronizations in Overview; initial sync may take
several minutes.

## 1. Test the connector

Configure a destination using the appropriate [connector guide](README.md).
Queue a test under **Connectors** and verify the message arrives in the correct
test chat. Confirm that delivery history says `sent`. A `pending` entry or a
successful button click alone is not delivery. Delivery hours and rate limits
also apply to test messages.

## 2. Inspect a rule without sending

Create one test asset and a rule limited to that asset or a small test group.
Rules are enabled by default: uncheck **Rule enabled** before saving this test
rule. Select your test connector and use **Test rule**. Record a stored
CVE with a positive match, check the matching evidence and compare the source
advisory. If none matches, this step is not yet passed. A deliberately chosen
test asset can exercise the flow but does not establish that your own systems
are affected.

## 3. Send one controlled CVE alert

Stop the monitor before enabling the test rule, so it does not evaluate all
stored CVEs while you prepare the targeted run. Keep the API container running:

```sh
docker compose stop monitor
docker compose exec vulnrelay vulnrelay rules list
```

Enable the test rule in the UI. Replace the placeholders with the actual rule
ID and CVE ID. Review the queue first: `deliver` handles the next eligible
message, which may be an older one if the queue is not empty.

```sh
docker compose exec vulnrelay vulnrelay queue status
docker compose exec vulnrelay vulnrelay evaluate --rule-id RULE_ID --cve-id CVE_ID --enqueue
docker compose exec vulnrelay vulnrelay deliver
docker compose exec vulnrelay vulnrelay history
```

For an empty queue and an eligible destination, expect one queued event, then a
`sent` delivery. Confirm the actual message contains the intended CVE, asset,
matching reason and source link. Delivery may remain queued outside configured
hours or during provider cooldowns; inspect the reason rather than assuming it
was sent.

## 4. Check duplicates and restart

Run the same targeted `evaluate` command again without changing the CVE, rule,
asset or destination. It should report `queued: 0`. Restart the API and verify
that the inventory and delivery history remain; repeat the evaluation:

```sh
docker compose restart vulnrelay
docker compose up -d --wait vulnrelay
docker compose exec vulnrelay vulnrelay history
docker compose exec vulnrelay vulnrelay evaluate --rule-id RULE_ID --cve-id CVE_ID --enqueue
```

The unchanged event should not be queued again. This does not establish an
exactly-once guarantee: a crash between provider acceptance and the local
acknowledgement can repeat a message. Different assets, rules or material
changes can also create distinct events.

## 5. Check cancellation and restore the monitor

With the monitor still stopped, create a second, initially disabled test rule
for the same asset and destination. Enable it, enqueue the targeted CVE using
its new rule ID, and disable it again **before** running `deliver`. Ensure the
test queue has no other eligible entries first: `deliver` selects the next
eligible entry across rules and destinations. The test entry should be marked
`cancelled`; no message should be sent for it. An HTTP request already in
flight cannot be recalled.

Disable both test rules, then restart the worker even if an earlier step failed:

```sh
docker compose up -d --wait monitor
docker compose exec monitor vulnrelay engine-health
```

Record the tested commit, environment and pass/fail result for each step; do
not include secrets, private chat IDs or inventory in public reports. A
[backup/restore rehearsal](backup-and-upgrade.md), source-outage recovery and
longer monitoring test remain separate release checks.
