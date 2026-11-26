# Generic JSON webhook

The generic webhook connector sends versioned JSON events to an endpoint you
operate. It supports normal alerts, security news, scheduled reports and test messages through
the persistent queue. Delivery hours, pacing, retries, history and at-least-once
semantics are shared with other connectors.

1. Put your endpoint in the server's private `.env`, for example
   `VULNRELAY_WEBHOOK_URL=https://receiver.example.org/alerts`. The URL must use
   HTTPS for public hosts and must not contain user information, a query string,
   a fragment, or percent-encoded path components. This initial version does not
   support arbitrary authorization headers.
2. Set an optional signing secret in `VULNRELAY_WEBHOOK_KEY` (at least 16 ASCII
   characters) and keep it private. If the value is empty, events are unsigned.
   Use independent variable names beginning with `VULNRELAY_WEBHOOK_URL` and
   `VULNRELAY_WEBHOOK_KEY` for multiple endpoints. The UI stores the variable
   names, not the endpoint value or signing secret.
3. Recreate both containers with `docker compose up -d --force-recreate`, then
   add a **Generic webhook** connector and attach it to a rule or report. Queue a
   test message and inspect delivery history. Tests obey connector delivery hours.

Each POST includes `Content-Type: application/json`, an `Idempotency-Key` equal
to the stable event ID and an `X-VulnRelay-Event` of `alert`, `news`, `report` or `test`.
For alerts, the JSON includes `schema_version`, `event_id`, `event_type`,
`message`, selected vulnerability metrics and the matching asset/rule reason.
News events include the source-attributed article details in `news`. Report
events include their period, entries and coverage information. Asset and
rule names are sent to the configured receiver. AI-generated text remains labeled
in the message and should not be treated as verified source data.

If a signing key is configured, `X-VulnRelay-Signature` contains `sha256=` plus
the HMAC-SHA256 hex digest of the **exact raw request body**. Verify it before
parsing or acting on the event, using a constant-time comparison. For example:

```python
import hashlib
import hmac

def verify(raw_body: bytes, received: str, secret: bytes) -> bool:
    expected = "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received)
```

The receiver should persist processed event IDs to handle retries and replayed
requests. A signature alone does not prevent replay, and `Idempotency-Key` only
helps when the receiver implements it. Any 2xx response acknowledges an event;
429 honors `Retry-After`, 5xx/transport failures retry, and other responses are
recorded as failures. Response bodies are not stored.

The hostname is resolved once and pinned to an allowed IP while TLS verifies the
original hostname; redirects are disabled. For a trusted private receiver, set
`VULNRELAY_WEBHOOK_ALLOW_PRIVATE_HOSTS=true`. Private HTTP endpoints require this
explicit opt-in; link-local/metadata endpoints remain blocked. Docker's localhost
is the container, not the VPS host. Automated tests mock the receiver; validate a
real endpoint under your control before relying on it.
