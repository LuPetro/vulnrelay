# Telegram setup

## Guided setup

Open **Connectors → Set up Telegram** to use the assistant:

1. Enter the **environment variable name** containing your bot token, such as
   `TELEGRAM_BOT_TOKEN` or `TELEGRAM_NEWS_BOT_TOKEN`. Expand **Where do I put the
   token?** for BotFather and server instructions. The actual token stays on
   your server. After changing `.env`, recreate both containers with
   `docker compose up -d --force-recreate --wait` from your installation folder.
2. Click **Check bot**. The assistant confirms the bot's username and offers a
   link to open that specific bot. Missing values, invalid tokens, connectivity
   failures and Telegram cooldowns have separate messages.
3. Send `/start` to the displayed bot, then click **Find chats**. Select a recent
   private chat, group or channel, or enter its ID/public channel username
   manually. The bot does not need to reply to `/start`.
4. Give the connector a name and optionally set delivery hours. Choose **Save
   connector and send test**. A message enters the persistent queue; keep the
   monitoring worker running. Delivery hours and rate limits apply to tests.
5. Wait for **Telegram accepted the test message**, then check the selected chat
   yourself. That status means Telegram accepted delivery, not that a person
   read it. If you close the assistant, the connector and queued test remain;
   inspect their status under **Connectors → Delivery history**.
6. Select the new connector as a destination in **News**, a notification rule
   or a scheduled report.

For a separate news bot, keep the existing token and add another variable:

```text
TELEGRAM_NEWS_BOT_TOKEN=YOUR_NEWS_BOT_TOKEN
```

Use `TELEGRAM_NEWS_BOT_TOKEN` as the variable name in the assistant. Never paste
the token itself into the name field, GitHub or support messages.

### When no chat appears

- Check the displayed bot username: a valid token may belong to a different bot.
- Send a **new** `/start` to that exact bot and repeat **Find chats**.
- For a group, add the bot and send `/start@your_bot_username`. For a channel,
  grant posting permission and publish a new channel message, or enter a known
  ID/public channel username manually.
- Telegram exposes only recent pending updates. Other bot software may already
  have received them. An active webhook prevents discovery: the assistant shows
  this and offers manual entry without changing the integration.
- If a test fails with HTTP 403, start the bot in the target private chat or
  check its group/channel membership and posting permissions.

The assistant requests bot identity and webhook status. Chat discovery is an
explicit action: it reads at most 100 recent updates, returns only chat IDs,
names and types, and does not persist message contents. It does not acknowledge
updates, change update subscriptions or delete webhooks. Shared persistent
cooldowns limit checks and respect Telegram's reported rate-limit delay.

## Manual setup and CLI

1. Create a bot using Telegram's verified @BotFather and obtain its token.
2. Put it in `.env` as `TELEGRAM_BOT_TOKEN=...`. Keep this file private. Recreate both Compose containers with `docker compose up -d --force-recreate` after changing credentials; a plain restart keeps the old container environment.
3. Add the bot to your group, or make it an administrator in your channel with permission to post. For a direct conversation, start the bot first. VulnRelay does not invite people or manage accounts.
4. Enter the chat's numeric ID (groups commonly use a negative ID), or a public channel username such as `@security_channel`, in a connector. Obtain IDs through Telegram's documented bot update tools or an administrator you trust. Do not paste bot tokens into third-party chat-ID sites or this repository.
5. The connector's token environment field is the variable name `TELEGRAM_BOT_TOKEN`, not the token itself. Different destinations can reference different environment variable names.
6. Click Test. This queues a test; the worker sends it. Inspect delivery history. Headless equivalents are `vulnrelay connectors test CONNECTOR_ID`, then `vulnrelay deliver`.

A missing token or a Telegram permission error becomes a visible failed delivery. Transport errors and server errors retry with backoff. Rate limits respect Telegram's reported cooldown. Unknown upstream error descriptions are not stored because they can contain secrets. Messages are plain text, safely limited below Telegram's length bound. Formatting and source records are treated as untrusted content.

A real bot token is not needed for tests or CI. Real destination delivery must be verified by the operator before production use. Reference: https://core.telegram.org/bots/api
