# Email delivery with SMTP

SMTP connectors send plain-text alerts and scheduled reports through an email
server that supports **STARTTLS with a valid certificate**. They use the existing
persistent queue, delivery hours, pacing, retries and history. The initial
implementation supports one sender and one recipient per connector; add separate
connectors for different recipients.

1. Put the SMTP server configuration in your private server `.env`:

   ```sh
   VULNRELAY_SMTP_HOST=mail.example.org
   VULNRELAY_SMTP_PORT=587
   VULNRELAY_SMTP_USER=your-smtp-username
   VULNRELAY_SMTP_PASSWORD=
   ```

   Fill the password in privately when authentication is required. The SMTP user and password can both be empty for a trusted server that does
   not require authentication. Some providers require an app-specific password;
   consult your provider's instructions. Never commit `.env` or paste its secrets
   into the web interface.
2. Recreate both containers with `docker compose up -d --force-recreate` after
   editing `.env`; a simple restart keeps the old environment.
3. In **Connectors → Add connector**, choose **Email via SMTP**. Enter the
   sender and recipient addresses and leave the environment variable names at
   their defaults, or choose additional variables beginning with
   `VULNRELAY_SMTP_HOST`, `VULNRELAY_SMTP_PORT`, `VULNRELAY_SMTP_USER` and
   `VULNRELAY_SMTP_PASSWORD` for a different server. The database stores variable
   names and addresses, not the SMTP password.
4. Add the destination to a rule or report and queue a test message. Inspect
   delivery history. Tests are subject to connector hours and pacing.

STARTTLS is mandatory, and the server certificate is verified against the
configured hostname. The hostname is resolved once and the connection is pinned
to an allowed address to prevent DNS rebinding. Public servers are supported by
default. A self-hosted SMTP server on a private network can be explicitly enabled
with `VULNRELAY_SMTP_ALLOW_PRIVATE_HOSTS=true`; link-local and metadata endpoints
remain blocked. From Docker, `localhost` refers to the container itself.

Implicit TLS on port 465, plaintext SMTP, OAuth, attachments, multiple recipients
in one connector, SMTPUTF8 addresses and non-ASCII login credentials are not supported in this initial
version. Temporary SMTP failures retry; permanent failures remain visible. A
connection failure after server acceptance can cause a repeat, so delivery is at
least once. Automated tests use a simulated server; verify a real test message
with your own SMTP account before relying on it.
