# ntfy and Gotify push notifications

Use ntfy or Gotify to receive alerts, scheduled reports and test messages in
their mobile or desktop clients. These connectors use the same persistent queue,
delivery hours, retry handling and history as Telegram. VulnRelay does not create
accounts or install and operate either server for you.

## ntfy

1. Choose an ntfy server and topic. **Public topics may be readable by other
   people**, including the names of your assets and rules in alerts. For private
   notifications, use a server and topic with suitable access controls; an
   unpredictable topic name alone is not authentication.
2. Set the server root URL in the private `.env` on the server as
   `VULNRELAY_NTFY_URL=https://your-ntfy.example`. Add
   `VULNRELAY_NTFY_TOKEN` when the server requires an access token; otherwise
   leave that value empty. Tokens must only be used with HTTPS.
3. Recreate both containers with `docker compose up -d --force-recreate`. In
   **Connectors → Add connector**, choose **ntfy push**, enter the topic and
   save. The form stores the environment variable names, never the URL value or
   token. Subscribe to the same topic in your ntfy client using its own access
   credentials if the server requires them.
4. Send a test notification and inspect delivery history. Test messages obey
   configured delivery hours. Connect the destination to a rule or a report.

The topic is limited to letters, digits, underscores and hyphens. Long messages
are truncated to stay below the usual ntfy 4096-byte message limit; the
truncation is indicated in the notification. See the [ntfy publishing
documentation](https://docs.ntfy.sh/publish/) for server-side configuration.

## Gotify

1. Create a Gotify application and obtain its application token. Install and
   sign in to the client separately as described in the [Gotify
   documentation](https://gotify.net/docs/pushmsg).
2. Set `VULNRELAY_GOTIFY_URL=https://your-gotify.example` and
   `VULNRELAY_GOTIFY_TOKEN` in the server's private `.env`. The token is
   required; HTTPS with a trusted certificate is mandatory when a token is used.
3. Recreate both containers, choose **Gotify push** under **Connectors**, save
   it, and send a test notification. Attach it to a rule or report.

## Server access and reliability

For multiple destinations, use unique variable names beginning with
`VULNRELAY_NTFY_URL` / `VULNRELAY_NTFY_TOKEN` or
`VULNRELAY_GOTIFY_URL` / `VULNRELAY_GOTIFY_TOKEN`, and select those names in
the form. Do not enter credential values into the form or send them in chat.
Protect your `.env` and your device subscriptions.

Public hosts require HTTPS. A deliberately configured private host requires
`VULNRELAY_PUSH_ALLOW_PRIVATE_HOSTS=true`. Only unauthenticated ntfy can use
HTTP on an opted-in private address: **Gotify and token-authenticated ntfy
require HTTPS** even on a private network. TLS certificates must be trusted by
the container; there is no option to bypass certificate verification. A
container's `localhost` refers to the container, not the VPS host.

The connector resolves and pins a permitted address and verifies the original
TLS hostname; redirects and link-local/metadata addresses are blocked. A 429
response postpones delivery, respecting `Retry-After` when supplied. Connectors
using the same server URL environment reference share a provider cooldown.
Server failures and network errors are retried; other rejected responses are
shown in delivery history. A crash after the remote server accepts a message but
before VulnRelay records success can cause a duplicate: delivery is at least
once, not exactly once. Automated tests use synthetic messages and a temporary
local test receiver; verify your own server and client before relying on them.
