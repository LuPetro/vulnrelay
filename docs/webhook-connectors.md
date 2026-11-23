# Discord and Slack webhooks

Discord and Slack destinations use the same persistent queue, delivery hours,
configurable pacing, history, retries, and rule selection as Telegram. Messages
contain the original metrics, source attribution, and match explanation. Discord
mentions are disabled; Slack messages use plain text. A rate limit postpones delivery
for the provider's reported cooldown and does not exhaust the retry budget.

1. Create a webhook using the [Discord channel integration](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) or a [Slack app with incoming webhooks enabled](https://api.slack.com/messaging/webhooks). The webhook determines the destination channel; VulnRelay does not grant workspace access.
2. Put its URL on the server in `.env`, for example `DISCORD_WEBHOOK_URL=...` or `SLACK_WEBHOOK_URL=...`. Treat it like a password. You can use different variable names for additional destinations. Never commit `.env`, enter the URL in the web interface, or post it in an issue.
3. Recreate both containers so their environment is refreshed: `docker compose up -d --force-recreate`. A restart alone does not reload `.env`. Native installs read `.env` in the working directory.
4. In **Connectors → Add connector**, choose Discord or Slack and enter the **name** of the environment variable, not its value. Configure delivery hours and minimum spacing if required. Add the destination to a rule.
5. Click **Test** and inspect delivery history. A test is queued and is also subject to delivery hours and rate limits. The operator must verify a real delivery independently; automated tests use mocked providers.

For safety only official `https://discord.com/api/webhooks/...` and `https://hooks.slack.com/services/...` endpoints are accepted, without redirects. Slack Gov, custom reverse proxies, and self-hosted webhook endpoints are not supported by these two connectors. A provider's non-rate client error remains visible as a failed delivery; service errors are retried. Neither provider offers an exactly-once guarantee through these webhooks.
