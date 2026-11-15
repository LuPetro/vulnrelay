# Delivery queue and Telegram pacing

The Overview and Connectors pages show database-wide counts, in-flight requests, the latest successful acknowledgement, recorded failures and each destination's next eligibility. These totals include all outbox records, not just the last 100 history rows. A recent worker heartbeat does not guarantee successful Telegram delivery. Read-only diagnostics are also available through `vulnrelay queue status` or `GET /api/queue/status`.

## Why messages wait

The long-running worker has no batch pause after 50 messages. Connector pacing, a scheduled retry, an in-flight request or a provider cooldown can defer a message. Failed/disabled/invalid destinations are visible separately; failed messages need explicit Retry. Use the Delivery history state filter to find failures even when thousands of newer pending records exist. HTTP 403 is a rejection rather than rate limiting. A Telegram 429 is shown as a rate limit with its persisted deadline.

Telegram [recommends at most one message per second in a single chat and limits groups to 20 messages per minute](https://core.telegram.org/bots/faq#my-bot-is-hitting-limits-how-do-i-avoid-this). A backlog of 1,000 individual messages to one group therefore takes at least about 50 minutes, before network overhead or additional cooldowns. Other applications using the same bot may also consume its allowance. The initial asset/rule correlation can queue existing stored CVEs, including historical KEV records; it is not restricted to CVEs published after the asset was added.

Edit a connector's **Minimum seconds between messages**. The default is 3.1 seconds to suit groups; private chats may use 1.1 seconds. Accepted values are 1.1–3600 seconds. The configured interval is a minimum, not a throughput guarantee. Same-token-reference, same-chat-identifier aliases use the longest interval among enabled aliases. The worker does not add a fixed one-second sleep after a processed message; it waits briefly when nothing is eligible.

Telegram's [retry_after](https://core.telegram.org/bots/api#responseparameters) is always respected and is calculated from response completion. HTTP 429 does not consume the six non-rate failure budget; actual request attempts remain visible. Non-rate transport/server failures still use bounded exponential retries, and terminal rejections fail immediately. An expired lease counts as an uncertain failed attempt. Provider deadlines survive restart and apply to connectors sharing the same token environment reference, including destinations added during a cooldown. This does not coordinate different installations, alternate environment references for the same token, or chat-ID/username aliases that resolve to the same real chat.

## Clear unwanted waiting messages

Choose **Clear waiting messages** in Overview or Connectors. VulnRelay obtains a fresh server snapshot, asks for confirmation, then discards only pending/retry records created at or before that snapshot. Newer records and in-flight requests are preserved; a request already being sent can still finish. The response reports how many were actually discarded.

Cleared events become `dismissed`; they are not deleted. Their event keys and history remain, preventing unchanged events from immediately refilling the queue. New materially changed events can still be queued when the rule allows re-notification. Dismissed messages have no Retry action. This does not remove CVE data, assets, rules or connector configuration.

Headless commands:

```sh
vulnrelay queue status
vulnrelay queue clear              # asks before discarding
vulnrelay queue clear --yes        # explicitly discard the current waiting snapshot
vulnrelay queue clear --connector CONNECTOR_ID --yes
```

API mutations require the usual authentication, request header and same-origin checks. `POST /api/queue/clear` accepts `{"before": UNIX_TIMESTAMP, "connector_id": "optional-id"}`. Obtain the timestamp from `/api/queue/status`; it is clamped to server time. Never delete outbox rows to empty the queue: that also removes duplicate protection.

## Sent counter and updating

The sent counter includes successfully acknowledged connector tests and CVE events. It does not include pending, retry, failed or dismissed events. It is not a count of distinct CVEs or recipients. The visual count is complete below 1,000 and uses a lowercase `k` above it; hover and assistive text retain the precise number. Only actual increases roll between old and new values; there is no invented counting through intermediate values. Pause/reduced-motion/hidden-tab preferences keep it static.

Overview/Connectors refresh status every five seconds while visible, separately from inventory/configuration loading. Versioned responses prevent older requests from overwriting newer status. Configuration keeps its normal refresh schedule. This is periodic synchronization, not an instantaneous stream.

This increment includes migration 0007. Follow the [backed-up Docker update procedure](catalog.md#update-and-test-an-existing-docker-installation); Compose runs migrations before readiness. Keep `.env`, project/image names and the data volume. Existing failed records are not silently retried by upgrading. Restoring an older application after changing connector settings may require the pre-upgrade backup; do not reset or delete the database to roll back.
