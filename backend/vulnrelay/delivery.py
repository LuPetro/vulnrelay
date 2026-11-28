"""Persistent notification delivery with expiring claims and bounded retries."""

import hashlib
import hmac
import json
import logging
import math
import os
import re
import smtplib
import socket
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from dotenv import dotenv_values
from pydantic import ValidationError
from sqlalchemy import bindparam, text
from sqlalchemy.engine import Engine

from vulnrelay.delivery_schedule import schedule_allows
from vulnrelay.pipeline import refresh_alert
from vulnrelay.queue import connector_provider_key, same_destination
from vulnrelay.schemas import Connector
from vulnrelay.store import get_document, list_documents

# HTTP client request logging would expose the bot token embedded in Telegram URLs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
MAX_FAILURES = 6


def _interval(document: dict) -> float:
    try:
        return Connector.model_validate(
            {k: v for k, v in document.items() if k != "id"}
        ).min_interval_seconds
    except ValidationError:
        return 3.1


@dataclass
class DeliveryResult:
    success: bool
    retryable: bool = False
    error: str = ""
    retry_after: float = 0
    rate_limited: bool = False


def render(payload: dict, *, max_bytes: int = 7600, ai_summary: str | None = None) -> str:
    if payload.get("test"):
        return "VulnRelay test notification. Your notification connector is working."
    if payload.get("news"):
        item = payload["item"]
        category = "Vulnerability news" if item["category"] == "vulnerability" else "Security news"
        heading = f"VulnRelay · {category}"
        footer = f"Source: {item['source_name']}\nPublished: {item['published'] or 'unknown'}\n{item['url']}"
        budget = max(0, max_bytes - len(f"{heading}\n\n{footer}".encode("utf-16-le")))
        title = item["title"].encode("utf-16-le")[:budget].decode("utf-16-le", errors="ignore")
        return f"{heading}\n{title}\n{footer}"
    if payload.get("digest"):

        def instant(value):
            return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M UTC")

        heading = [
            f"VulnRelay report · {payload['name']}",
            f"{'Your matching assets' if payload['scope'] == 'relevant' else 'Worldwide CVEs'} · {instant(payload['period_start'])} to {instant(payload['period_end'])}",
        ]
        footer = [
            f"Screened {payload['scanned']} of {payload['candidates']} locally stored candidates.",
            f"NVD last successful sync: {payload['nvd_synced'] or 'unknown'}.",
            "Only locally synchronized NVD records with a publication date; coverage can be incomplete.",
        ]
        entries = []
        for item in payload["entries"]:
            epss = "unknown" if item["epss"] is None else f"{item['epss']:.1%}"
            line = (
                f"{item['id']} · {item['severity'] or 'unknown'} · CVSS {item['cvss'] if item['cvss'] is not None else 'unknown'} · EPSS {epss} · KEV {item['kev'] if item['kev'] is not None else 'unknown'}\n"
                f"https://nvd.nist.gov/vuln/detail/{item['id']}"
            )
            if item.get("match"):
                reason = item["match"]
                line += f"\nWhy: {reason['asset']} · {reason['rule']} · {reason['confidence']} match. {reason['explanation']}"
            candidate = "\n".join(
                [*heading, f"Showing {len(entries) + 1} entries:", *entries, line, *footer]
            )
            if len(candidate.encode("utf-16-le")) > max_bytes:
                break
            entries.append(line)
        return "\n".join([*heading, f"Showing {len(entries)} entries:", *entries, *footer])
    vulnerability = payload["vulnerability"]

    def metric(value):
        return "unknown" if value is None else str(value)

    epss = "unknown" if vulnerability["epss"] is None else f"{vulnerability['epss']:.1%}"
    lines = [
        f"VulnRelay · {vulnerability['id']}",
        f"Severity: {vulnerability['severity'] or 'unknown'} · CVSS: {metric(vulnerability['cvss'])}",
        f"EPSS: {epss} (date: {vulnerability.get('epss_date') or 'unknown'}) · KEV: {metric(vulnerability['kev'])}",
        f"Why: rule '{payload['rule']}', asset '{payload['asset']}'.",
        f"Match: {payload['match']['confidence']} · {payload['match']['explanation']}",
    ]
    if vulnerability.get("cvss_source"):
        lines.append(f"CVSS assessment: {vulnerability['cvss_source']}")
    sources = " · ".join(vulnerability.get("sources") or ["NVD", "CISA KEV", "FIRST EPSS"])
    footer = [
        f"https://nvd.nist.gov/vuln/detail/{vulnerability['id']}",
        f"Sources: {sources} (only available metrics shown).",
    ]
    if "OpenCVE" in vulnerability.get("sources", []):
        from vulnrelay.opencve import record_url

        footer.insert(1, record_url(vulnerability["id"]))
    if payload["match"].get("method") == "osv_package_version":
        from urllib.parse import quote

        footer.insert(
            1,
            f"https://osv.dev/vulnerability/{quote(payload['match']['evidence']['osv_id'], safe='')}",
        )
    prefix, suffix = "\n".join(lines), "\n".join(footer)
    safe_summary = (
        ai_summary.encode("utf-16-le", errors="replace")[:1200].decode("utf-16-le", errors="ignore")
        if ai_summary
        else ""
    )
    generated = f"AI-generated summary (unverified):\n{safe_summary}" if safe_summary else ""
    middle = ""
    if payload["format"] == "detailed":
        recommendation = "Verify the installed version and review official vendor guidance before deciding remediation."
        # Reserve room for attribution and the canonical source link, even with emoji.
        reserved = len(
            (prefix + "\n\n" + recommendation + "\n" + generated + "\n" + suffix).encode(
                "utf-16-le"
            )
        )
        budget = max(0, max_bytes - reserved)
        description = (
            (vulnerability.get("description") or "")
            .encode("utf-16-le")[:budget]
            .decode("utf-16-le", errors="ignore")
        )
        middle = description + "\n" + recommendation
    return "\n".join(part for part in (prefix, middle, generated, suffix) if part)


def _secret(reference: str) -> str:
    return os.environ.get(reference, dotenv_values(".env").get(reference) or "")


def send_telegram(
    connector: Connector, message: str, *, client: httpx.Client | None = None
) -> DeliveryResult:
    token = _secret(connector.token_env)
    if not re.fullmatch(r"\d{5,20}:[A-Za-z0-9_-]{20,200}", token):
        return DeliveryResult(
            False, error="Telegram token environment variable is missing or invalid"
        )
    owned = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)
    try:
        response = client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": connector.chat_id,
                "text": message,
                "link_preview_options": {"is_disabled": True},
            },
        )
        try:
            body = response.json()
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        code = response.status_code
        if code == 200 and body.get("ok") is True:
            return DeliveryResult(True)
        if code == 429 or body.get("error_code") == 429:
            parameters = body.get("parameters")
            delay = parameters.get("retry_after", 60) if isinstance(parameters, dict) else 60
            try:
                delay = float(delay) if type(delay) in (int, float) else 60
                delay = delay if math.isfinite(delay) else 60
            except (OverflowError, ValueError):
                delay = 60
            return DeliveryResult(
                False, True, "Telegram rate limit", max(1, delay), rate_limited=True
            )
        return DeliveryResult(False, code >= 500, f"Telegram delivery rejected (HTTP {code})")
    except httpx.HTTPError:
        # Never persist exception strings: Telegram URLs contain secrets.
        return DeliveryResult(False, True, "Telegram transport failed")
    finally:
        if owned:
            client.close()


def send_webhook(
    connector: Connector, message: str, *, client: httpx.Client | None = None
) -> DeliveryResult:
    """Use only official webhook hosts and never log the secret-bearing URL."""
    kind = connector.kind
    name = "Discord" if kind == "discord" else "Slack"
    url = _secret(connector.webhook_env)
    patterns = {
        "discord": r"https://discord\.com/api/webhooks/[0-9]{10,30}/[A-Za-z0-9_.-]{20,200}",
        "slack": r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
    }
    if kind not in patterns or not re.fullmatch(patterns[kind], url):
        return DeliveryResult(
            False, error=f"{name} webhook environment variable is missing or invalid"
        )
    owned = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)
    payload = (
        {"content": message, "allowed_mentions": {"parse": []}}
        if kind == "discord"
        else {"text": message, "mrkdwn": False}
    )
    try:
        response = client.post(url, json=payload, follow_redirects=False)
        if (kind == "discord" and response.status_code in (200, 204)) or (
            kind == "slack" and response.status_code == 200 and response.text.strip() == "ok"
        ):
            return DeliveryResult(True)
        if kind == "slack" and response.status_code == 200:
            return DeliveryResult(False, error="Slack did not acknowledge delivery (HTTP 200)")
        if response.status_code == 429:
            raw_delay = response.headers.get("Retry-After", "")
            if kind == "discord":
                try:
                    body = response.json()
                    raw_delay = (
                        body.get("retry_after", raw_delay) if isinstance(body, dict) else raw_delay
                    )
                except ValueError:
                    pass
            try:
                delay = float(raw_delay)
                delay = delay if math.isfinite(delay) else 60
            except (ValueError, TypeError, OverflowError):
                delay = 60
            return DeliveryResult(False, True, f"{name} rate limit", max(1, delay), True)
        return DeliveryResult(
            False,
            response.status_code >= 500,
            f"{name} delivery rejected (HTTP {response.status_code})",
        )
    except httpx.HTTPError:
        return DeliveryResult(False, True, f"{name} transport failed")
    finally:
        if owned:
            client.close()


def send_generic_webhook(
    connector: Connector,
    payload: dict,
    message: str,
    *,
    message_id: str,
    client: httpx.Client | None = None,
) -> DeliveryResult:
    """Send a versioned JSON event to an explicitly configured, pinned endpoint."""
    from vulnrelay.ai import AIError, _pin_endpoint
    from vulnrelay.config import get_settings
    from vulnrelay.nvd import retry_after_seconds

    endpoint = _secret(connector.webhook_env).strip()
    signing_key = _secret(connector.webhook_signing_env)
    if signing_key and (
        not signing_key.isascii()
        or len(signing_key) < 16
        or len(signing_key) > 4096
        or "\r" in signing_key
        or "\n" in signing_key
    ):
        return DeliveryResult(False, error="Webhook signing key is invalid; use at least 16 bytes")
    try:
        pinned_url, host, tls_host = _pin_endpoint(
            endpoint, get_settings().webhook_allow_private_hosts
        )
    except AIError:
        return DeliveryResult(False, error="Webhook URL is invalid, unavailable, or not permitted")
    event_type = (
        "test"
        if payload.get("test")
        else "news"
        if payload.get("news")
        else "report"
        if payload.get("digest")
        else "alert"
    )
    data = {
        "schema_version": 1,
        "event_id": message_id,
        "event_type": event_type,
        "message": message,
    }
    if event_type == "alert":
        vulnerability = payload["vulnerability"]
        data["vulnerability"] = {
            key: vulnerability.get(key)
            for key in (
                "id",
                "cvss",
                "cvss_source",
                "severity",
                "epss",
                "epss_date",
                "kev",
                "sources",
            )
        }
        data["reason"] = {
            "asset": payload["asset"],
            "rule": payload["rule"],
            "method": payload["match"].get("method"),
            "confidence": payload["match"].get("confidence"),
            "explanation": payload["match"].get("explanation"),
        }
    elif event_type == "report":
        data["report"] = {
            key: payload.get(key)
            for key in (
                "name",
                "scope",
                "period_start",
                "period_end",
                "entries",
                "scanned",
                "candidates",
                "nvd_synced",
            )
        }
    elif event_type == "news":
        data["news"] = payload["item"]
    body = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8", errors="replace"
    )
    headers = {
        "Host": host,
        "Content-Type": "application/json",
        "Idempotency-Key": message_id,
        "X-VulnRelay-Event": event_type,
    }
    if signing_key:
        headers["X-VulnRelay-Signature"] = (
            "sha256=" + hmac.new(signing_key.encode(), body, hashlib.sha256).hexdigest()
        )
    owned = client is None
    client = client or httpx.Client(
        timeout=httpx.Timeout(15, connect=5), trust_env=False, follow_redirects=False
    )
    try:
        with client.stream(
            "POST",
            pinned_url,
            content=body,
            headers=headers,
            follow_redirects=False,
            extensions={"sni_hostname": tls_host},
        ) as response:
            if 200 <= response.status_code < 300:
                return DeliveryResult(True)
            if response.status_code == 429:
                delay = max(1, retry_after_seconds(response) or 60)
                return DeliveryResult(False, True, "Webhook rate limit", delay, True)
            return DeliveryResult(
                False,
                response.status_code >= 500,
                f"Webhook delivery rejected (HTTP {response.status_code})",
            )
    except httpx.HTTPError:
        return DeliveryResult(False, True, "Webhook transport failed")
    finally:
        if owned:
            client.close()


def send_push(
    connector: Connector, message: str, *, client: httpx.Client | None = None
) -> DeliveryResult:
    """Deliver to an opt-in ntfy or Gotify server without forwarding secrets to redirects."""
    from vulnrelay.ai import AIError, _pin_endpoint
    from vulnrelay.config import get_settings
    from vulnrelay.nvd import retry_after_seconds

    kind = connector.kind
    name = "ntfy" if kind == "ntfy" else "Gotify"
    base = _secret(connector.webhook_env).strip().rstrip("/")
    token = _secret(connector.push_token_env)
    if not base:
        return DeliveryResult(False, error=f"{name} server URL environment variable is missing")
    if kind == "gotify" and not token:
        return DeliveryResult(
            False, error="Gotify application token environment variable is missing"
        )
    if token and (len(token) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token)):
        return DeliveryResult(False, error=f"{name} token environment variable is invalid")
    endpoint = base + ("/" if kind == "ntfy" else "/message")
    if token and not endpoint.startswith("https://"):
        return DeliveryResult(False, error=f"{name} tokens require HTTPS")
    try:
        url, host, tls_host = _pin_endpoint(endpoint, get_settings().push_allow_private_hosts)
    except AIError:
        return DeliveryResult(
            False, error=f"{name} server URL is invalid, unavailable, or not permitted"
        )
    if kind == "ntfy":
        # ntfy treats messages over 4096 UTF-8 bytes as attachments.
        encoded = message.encode("utf-8", errors="replace")
        if len(encoded) > 3900:
            message = encoded[:3860].decode("utf-8", errors="ignore") + "\n[Message truncated]"
        data = {
            "topic": connector.ntfy_topic,
            "title": "VulnRelay",
            "message": message,
            "priority": 3,
        }
    else:
        data = {"title": "VulnRelay", "message": message, "priority": 5}
    headers = {"Host": host}
    if token:
        headers["Authorization" if kind == "ntfy" else "X-Gotify-Key"] = (
            f"Bearer {token}" if kind == "ntfy" else token
        )
    owned = client is None
    client = client or httpx.Client(
        timeout=httpx.Timeout(15, connect=5), trust_env=False, follow_redirects=False
    )
    try:
        with client.stream(
            "POST",
            url,
            json=data,
            headers=headers,
            follow_redirects=False,
            extensions={"sni_hostname": tls_host},
        ) as response:
            if 200 <= response.status_code < 300:
                return DeliveryResult(True)
            if response.status_code == 429:
                return DeliveryResult(
                    False,
                    True,
                    f"{name} rate limit",
                    max(1, retry_after_seconds(response) or 60),
                    True,
                )
            return DeliveryResult(
                False,
                response.status_code >= 500,
                f"{name} delivery rejected (HTTP {response.status_code})",
            )
    except httpx.HTTPError:
        return DeliveryResult(False, True, f"{name} transport failed")
    finally:
        if owned:
            client.close()


class _PinnedSMTP(smtplib.SMTP):
    """Connect to a resolved IP while STARTTLS authenticates the original hostname."""

    def __init__(self, host: str, address: str, port: int):
        self._pinned_address = address
        super().__init__(host=host, port=port, timeout=15, local_hostname="localhost")

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self._pinned_address, port), timeout)


def send_smtp(connector: Connector, message: str, *, message_id: str) -> DeliveryResult:
    """Send one plain-text email over certificate-verified STARTTLS."""
    from vulnrelay.ai import AIError, _pin_endpoint
    from vulnrelay.config import get_settings

    host = _secret(connector.smtp_host_env).strip()
    port_text = _secret(connector.smtp_port_env) or "587"
    username, password = _secret(connector.smtp_user_env), _secret(connector.smtp_password_env)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}", host):
        return DeliveryResult(False, error="SMTP host environment variable is missing or invalid")
    if not re.fullmatch(r"[0-9]{1,5}", port_text) or not 1 <= int(port_text) <= 65535:
        return DeliveryResult(False, error="SMTP port environment variable is invalid")
    if bool(username) != bool(password) or any(
        len(value) > 4096 or not value.isascii() or "\r" in value or "\n" in value
        for value in (username, password)
    ):
        return DeliveryResult(
            False, error="SMTP authentication environment variables are incomplete or invalid"
        )
    port = int(port_text)
    try:
        pinned_url, _, original_host = _pin_endpoint(
            f"https://{host}:{port}/", get_settings().smtp_allow_private_hosts
        )
        address = urlsplit(pinned_url).hostname
        if not address:
            raise AIError("Invalid address")
    except AIError:
        return DeliveryResult(False, error="SMTP host could not be resolved or is not permitted")
    email = EmailMessage()
    email["From"] = connector.smtp_from
    email["To"] = connector.smtp_to
    email["Subject"] = "VulnRelay security notification"
    email["Message-ID"] = f"<{message_id}@vulnrelay.local>"
    email.set_content(message)
    smtp = None
    try:
        smtp = _PinnedSMTP(original_host, address, port)
        smtp.ehlo_or_helo_if_needed()
        smtp.starttls(context=ssl.create_default_context())
        if username:
            smtp.login(username, password)
        refused = smtp.send_message(email)
        if refused:
            codes = [item[0] for item in refused.values() if isinstance(item, tuple) and item]
            retryable = bool(
                codes and all(isinstance(code, int) and 400 <= code < 500 for code in codes)
            )
            return DeliveryResult(False, retryable, "SMTP recipient rejected the message")
        # The message was already accepted; do not invent a failure on QUIT.
        with suppress(smtplib.SMTPException, OSError):
            smtp.quit()
        return DeliveryResult(True)
    except ssl.SSLCertVerificationError:
        return DeliveryResult(False, error="SMTP TLS certificate verification failed")
    except smtplib.SMTPNotSupportedError:
        return DeliveryResult(False, error="SMTP server does not support required STARTTLS")
    except smtplib.SMTPRecipientsRefused as error:
        codes = [item[0] for item in error.recipients.values() if isinstance(item, tuple) and item]
        retryable = bool(
            codes and all(isinstance(code, int) and 400 <= code < 500 for code in codes)
        )
        return DeliveryResult(False, retryable, "SMTP recipient rejected the message")
    except smtplib.SMTPResponseException as error:
        return DeliveryResult(
            False, 400 <= error.smtp_code < 500, f"SMTP delivery rejected (code {error.smtp_code})"
        )
    except (smtplib.SMTPException, OSError):
        return DeliveryResult(False, True, "SMTP connection failed")
    finally:
        if smtp:
            with suppress(smtplib.SMTPException, OSError):
                smtp.close()


def enqueue_test(engine: Engine, connector_id: str) -> str:
    if connector_id not in {row["id"] for row in list_documents(engine, "connectors")}:
        raise ValueError("Connector not found")
    message_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO outbox (id, event_key, connector_id, payload,
            state, attempts, available_at, created_at) VALUES (:id, :id, :connector, :payload,
            'pending', 0, :now, :now)"""),
            {
                "id": message_id,
                "connector": connector_id,
                "payload": json.dumps({"test": True}),
                "now": time.time(),
            },
        )
    return message_id


def deliver_one(
    engine: Engine, *, now: float | None = None, client: httpx.Client | None = None
) -> dict | None:
    current = time.time() if now is None else now
    documents = list_documents(engine, "connectors")
    outside_schedule = []
    for document in documents:
        try:
            candidate = Connector.model_validate({k: v for k, v in document.items() if k != "id"})
        except ValidationError:
            continue  # Invalid/disabled destinations retain their normal cleanup behavior.
        if candidate.enabled and not schedule_allows(candidate.delivery_schedule, current):
            outside_schedule.append(document["id"])
    lease = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text("""UPDATE outbox SET
            state=CASE WHEN failures+1>=:maximum THEN 'failed' ELSE 'retry' END,
            failures=failures+1, available_at=:now, lease_until=NULL, lease_token=NULL,
            last_error='Delivery claim expired; previous request outcome is unknown'
            WHERE state='sending' AND lease_until<=:now"""),
            {"now": current, "maximum": MAX_FAILURES},
        )
        provider_limits = {
            row.id: row.available_at
            for row in connection.execute(
                text("SELECT id, available_at FROM connector_limits WHERE available_at>:now"),
                {"now": current},
            )
        }
        blocked = outside_schedule + [
            item["id"] for item in documents if connector_provider_key(item) in provider_limits
        ]
        row = (
            connection.execute(
                text("""UPDATE outbox SET state='sending', attempts=attempts+1,
            lease_until=:until, lease_token=:lease WHERE id=(
                SELECT id FROM outbox WHERE failures<:maximum
                AND state IN ('pending','retry') AND available_at<=:now
                AND connector_id NOT IN :blocked
                AND NOT EXISTS (SELECT 1 FROM connector_limits l WHERE l.id=outbox.connector_id AND l.available_at>:now)
                AND NOT EXISTS (SELECT 1 FROM outbox active WHERE active.connector_id=outbox.connector_id
                    AND active.state='sending' AND active.lease_until>:now)
                ORDER BY created_at, id LIMIT 1)
            RETURNING *""").bindparams(bindparam("blocked", expanding=True)),
                {
                    "now": current,
                    "until": current + 120,
                    "lease": lease,
                    "maximum": MAX_FAILURES,
                    "blocked": blocked,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        connector = next((item for item in documents if item["id"] == row["connector_id"]), None)
        siblings = [connector] if connector else []
        if connector:
            siblings = [
                item
                for item in documents
                if item.get("enabled", True) and same_destination(item, connector)
            ]
        interval = max((_interval(item) for item in siblings), default=3.1)
        for sibling_id in {row["connector_id"], *(item["id"] for item in siblings)}:
            connection.execute(
                text("""INSERT INTO connector_limits (id, available_at) VALUES (:id,:available)
                ON CONFLICT(id) DO UPDATE SET available_at=CASE
                WHEN connector_limits.available_at>excluded.available_at THEN connector_limits.available_at
                ELSE excluded.available_at END"""),
                {"id": sibling_id, "available": current + interval},
            )
    cancellation = None
    attempted = False
    if not connector or not connector.get("enabled", True):
        outcome = DeliveryResult(False, error="Connector disabled or removed")
    else:
        try:
            config = Connector.model_validate({k: v for k, v in connector.items() if k != "id"})
        except ValidationError:
            config = None
        payload, cancellation = refresh_alert(engine, json.loads(row["payload"]), connector["id"])
        if config is None:
            outcome = DeliveryResult(False, error="Connector configuration is invalid")
        elif cancellation:
            outcome = DeliveryResult(False, error=cancellation)
        else:
            ai_summary = None
            if not payload.get("test") and not payload.get("digest") and not payload.get("news"):
                try:
                    from vulnrelay.ai import summarize

                    ai_summary = summarize(engine, payload["vulnerability"])
                except Exception:  # noqa: BLE001 - AI must never prevent a verified alert
                    logging.getLogger(__name__).warning(
                        "AI summary unavailable; sending source alert"
                    )
            # Configuration may change while rule/asset revalidation is running. Defer
            # changed destinations for a fresh claim; never send using an old schedule.
            before_send = current if now is not None else time.time()
            latest = get_document(engine, "connectors", connector["id"])
            if latest != connector or not schedule_allows(config.delivery_schedule, before_send):
                with engine.begin() as connection:
                    connection.execute(
                        text("""UPDATE outbox SET state=:state, attempts=attempts-1,
                        lease_until=NULL, lease_token=NULL
                        WHERE id=:id AND lease_token=:lease"""),
                        {
                            "state": "pending"
                            if row["attempts"] == 1 and not row["last_error"]
                            else "retry",
                            "id": row["id"],
                            "lease": lease,
                        },
                    )
                    for sibling_id in {row["connector_id"], *(item["id"] for item in siblings)}:
                        connection.execute(
                            text("""UPDATE connector_limits SET available_at=:now
                            WHERE id=:id AND available_at=:reserved AND rate_limited_until<=:now"""),
                            {"id": sibling_id, "now": before_send, "reserved": current + interval},
                        )
                return None
            with engine.begin() as connection:
                updated = connection.execute(
                    text("UPDATE outbox SET payload=:payload WHERE id=:id AND lease_token=:lease"),
                    {
                        "payload": json.dumps(payload, ensure_ascii=False),
                        "id": row["id"],
                        "lease": lease,
                    },
                )
                if updated.rowcount != 1:
                    return None
            attempted = True
            if config.kind == "telegram":
                outcome = send_telegram(
                    config, render(payload, ai_summary=ai_summary), client=client
                )
            elif config.kind == "smtp":
                outcome = send_smtp(
                    config, render(payload, ai_summary=ai_summary), message_id=row["id"]
                )
            elif config.kind == "webhook":
                outcome = send_generic_webhook(
                    config,
                    payload,
                    render(payload, ai_summary=ai_summary),
                    message_id=row["id"],
                    client=client,
                )
            elif config.kind in ("ntfy", "gotify"):
                outcome = send_push(
                    config, render(payload, max_bytes=2200, ai_summary=ai_summary), client=client
                )
            else:
                outcome = send_webhook(
                    config, render(payload, max_bytes=3600, ai_summary=ai_summary), client=client
                )
    finished = current if now is not None else time.time()
    failures = row["failures"] + (not outcome.success and not outcome.rate_limited)
    state = (
        "cancelled"
        if cancellation
        else "sent"
        if outcome.success
        else "retry"
        if outcome.retryable and failures < MAX_FAILURES
        else "failed"
    )
    delay = outcome.retry_after if outcome.rate_limited else min(3600, 2**failures * 15)
    with engine.begin() as connection:
        if not attempted:
            for sibling_id in {row["connector_id"], *(item["id"] for item in siblings)}:
                connection.execute(
                    text("""UPDATE connector_limits SET available_at=:now
                    WHERE id=:id AND available_at=:reserved AND rate_limited_until<=:now"""),
                    {"id": sibling_id, "now": finished, "reserved": current + interval},
                )
        connection.execute(
            text("""UPDATE outbox SET state=:state, available_at=:available, failures=:failures,
            sent_at=:sent, lease_until=NULL, lease_token=NULL, last_error=:error
            WHERE id=:id AND lease_token=:lease"""),
            {
                "state": state,
                "available": finished + delay,
                "sent": finished if outcome.success else None,
                "failures": failures,
                "error": outcome.error or None,
                "id": row["id"],
                "lease": lease,
            },
        )
        if outcome.rate_limited and connector:
            reference = connector_provider_key(connector)
            targets = {reference} | {
                item["id"] for item in documents if connector_provider_key(item) == reference
            }
            for target in targets:
                connection.execute(
                    text("""INSERT INTO connector_limits (id,available_at,rate_limited_until)
                    VALUES (:id,:until,:until) ON CONFLICT(id) DO UPDATE SET
                    available_at=CASE WHEN connector_limits.available_at>:until THEN connector_limits.available_at ELSE :until END,
                    rate_limited_until=CASE WHEN connector_limits.rate_limited_until>:until THEN connector_limits.rate_limited_until ELSE :until END"""),
                    {"id": target, "until": finished + outcome.retry_after},
                )
    return {
        "id": row["id"],
        "state": state,
        "attempts": row["attempts"],
        "error": outcome.error or None,
    }


def history(
    engine: Engine, limit: int = 100, state: str | None = None, message_id: str | None = None
) -> list[dict]:
    identity_filter = " AND id=:message_id" if message_id is not None else ""
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text(
                    """SELECT id, connector_id, state,
            attempts, failures, created_at, sent_at, available_at, last_error FROM outbox WHERE (:state IS NULL OR state=:state)"""
                    + identity_filter
                    + " ORDER BY created_at DESC, id DESC LIMIT :limit"
                ),
                {"limit": min(1000, max(1, limit)), "state": state, "message_id": message_id},
            ).mappings()
        ]


def retry_failed(engine: Engine, message_id: str) -> bool:
    """Explicit operator retry of a terminal failure, retaining the event identity."""
    with engine.begin() as connection:
        result = connection.execute(
            text("""UPDATE outbox SET state='retry', attempts=0, failures=0,
            available_at=:now, lease_until=NULL, lease_token=NULL, last_error=NULL
            WHERE id=:id AND state='failed'"""),
            {"id": message_id, "now": time.time()},
        )
        return result.rowcount == 1
