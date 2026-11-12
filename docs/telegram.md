# Telegram setup

1. Create a bot using Telegram's verified @BotFather and obtain its token.
2. Put it in `.env` as `TELEGRAM_BOT_TOKEN=...`. Keep this file private. Restart both Compose services after changing credentials.
3. Add the bot to your group, or make it an administrator in your channel with permission to post. For a direct conversation, start the bot first. VulnRelay does not invite people or manage accounts.
4. Enter the chat's numeric ID (groups commonly use a negative ID), or a public channel username such as `@security_channel`, in a connector. Obtain IDs through Telegram's documented bot update tools or an administrator you trust. Do not paste bot tokens into third-party chat-ID sites or this repository.
5. The connector's token environment field is the variable name `TELEGRAM_BOT_TOKEN`, not the token itself. Different destinations can reference different environment variable names.
6. Click Test. This queues a test; the worker sends it. Inspect delivery history. Headless equivalents are `vulnrelay connectors test CONNECTOR_ID`, then `vulnrelay deliver`.

A missing token or a Telegram permission error becomes a visible failed delivery. Transport errors and server errors retry with backoff. Rate limits respect Telegram's reported cooldown. Unknown upstream error descriptions are not stored because they can contain secrets. Messages are plain text, safely limited below Telegram's length bound. Formatting and source records are treated as untrusted content.

A real bot token is not needed for tests or CI. Real destination delivery must be verified by the operator before production use. Reference: https://core.telegram.org/bots/api
