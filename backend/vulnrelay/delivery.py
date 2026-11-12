"""Persistent Telegram delivery with expiring claims and bounded retries (at least once)."""

import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from uuid import uuid4

import httpx
from dotenv import dotenv_values
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.schemas import Connector
from vulnrelay.store import list_documents

# HTTP client request logging would expose the bot token embedded in Telegram URLs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
MAX_ATTEMPTS = 6


@dataclass
class DeliveryResult:
    success: bool
    retryable: bool = False
    error: str = ""
    retry_after: float = 0


def render(payload: dict) -> str:
    if payload.get("test"):
        return "VulnRelay test notification. Your Telegram connector is working."
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
    footer = [
        f"https://nvd.nist.gov/vuln/detail/{vulnerability['id']}",
        "Sources: NVD · CISA KEV · FIRST EPSS (only available metrics shown).",
    ]
    prefix, suffix = "\n".join(lines), "\n".join(footer)
    middle = ""
    if payload["format"] == "detailed":
        recommendation = "Verify the installed version and review official vendor guidance before deciding remediation."
        # Reserve room for attribution and the canonical source link, even with emoji.
        reserved = len((prefix + "\n\n" + recommendation + "\n" + suffix).encode("utf-16-le"))
        budget = max(0, 7600 - reserved)
        description = (
            (vulnerability.get("description") or "")
            .encode("utf-16-le")[:budget]
            .decode("utf-16-le", errors="ignore")
        )
        middle = description + "\n" + recommendation
    return "\n".join(part for part in (prefix, middle, suffix) if part)


def send_telegram(
    connector: Connector, message: str, *, client: httpx.Client | None = None
) -> DeliveryResult:
    token = os.environ.get(
        connector.token_env, dotenv_values(".env").get(connector.token_env) or ""
    )
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
            delay = float(delay) if isinstance(delay, (int, float)) and math.isfinite(delay) else 60
            return DeliveryResult(False, True, "Telegram rate limit", max(1, min(delay, 86400)))
        return DeliveryResult(False, code >= 500, f"Telegram delivery rejected (HTTP {code})")
    except httpx.HTTPError:
        # Never persist exception strings: Telegram URLs contain secrets.
        return DeliveryResult(False, True, "Telegram transport failed")
    finally:
        if owned:
            client.close()


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
    lease = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text("""UPDATE outbox SET state='failed', last_error='Delivery claim expired at attempt limit'
            WHERE state='sending' AND lease_until<=:now AND attempts>=:maximum"""),
            {"now": current, "maximum": MAX_ATTEMPTS},
        )
        row = (
            connection.execute(
                text("""UPDATE outbox SET state='sending', attempts=attempts+1,
            lease_until=:until, lease_token=:lease WHERE id=(
                SELECT id FROM outbox WHERE attempts<:maximum AND (
                    (state IN ('pending','retry') AND available_at<=:now) OR
                    (state='sending' AND lease_until<=:now))
                AND NOT EXISTS (SELECT 1 FROM connector_limits l WHERE l.id=outbox.connector_id AND l.available_at>:now)
                ORDER BY created_at, id LIMIT 1)
            RETURNING *"""),
                {"now": current, "until": current + 120, "lease": lease, "maximum": MAX_ATTEMPTS},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        connection.execute(
            text("""INSERT INTO connector_limits (id, available_at) VALUES (:id,:available)
            ON CONFLICT(id) DO UPDATE SET available_at=excluded.available_at"""),
            {"id": row["connector_id"], "available": current + 1.1},
        )
    connector = next(
        (
            item
            for item in list_documents(engine, "connectors")
            if item["id"] == row["connector_id"]
        ),
        None,
    )
    if not connector or not connector["enabled"]:
        outcome = DeliveryResult(False, error="Connector disabled or removed")
    else:
        config = Connector.model_validate({k: v for k, v in connector.items() if k != "id"})
        outcome = send_telegram(config, render(json.loads(row["payload"])), client=client)
    state = (
        "sent"
        if outcome.success
        else "retry"
        if outcome.retryable and row["attempts"] < MAX_ATTEMPTS
        else "failed"
    )
    delay = max(outcome.retry_after, min(3600, 2 ** row["attempts"] * 15))
    with engine.begin() as connection:
        connection.execute(
            text("""UPDATE outbox SET state=:state, available_at=:available,
            sent_at=:sent, lease_until=NULL, lease_token=NULL, last_error=:error
            WHERE id=:id AND lease_token=:lease"""),
            {
                "state": state,
                "available": current + delay,
                "sent": current if outcome.success else None,
                "error": outcome.error or None,
                "id": row["id"],
                "lease": lease,
            },
        )
        if outcome.retry_after:
            connection.execute(
                text("UPDATE connector_limits SET available_at=:available WHERE id=:id"),
                {"id": row["connector_id"], "available": current + outcome.retry_after},
            )
    return {
        "id": row["id"],
        "state": state,
        "attempts": row["attempts"],
        "error": outcome.error or None,
    }


def history(engine: Engine, limit: int = 100) -> list[dict]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text("""SELECT id, connector_id, state,
            attempts, created_at, sent_at, available_at, last_error FROM outbox ORDER BY created_at DESC LIMIT :limit"""),
                {"limit": min(1000, max(1, limit))},
            ).mappings()
        ]


def retry_failed(engine: Engine, message_id: str) -> bool:
    """Explicit operator retry of a terminal failure, retaining the event identity."""
    with engine.begin() as connection:
        result = connection.execute(
            text("""UPDATE outbox SET state='retry', attempts=0,
            available_at=:now, lease_until=NULL, lease_token=NULL, last_error=NULL
            WHERE id=:id AND state='failed'"""),
            {"id": message_id, "now": time.time()},
        )
        return result.rowcount == 1
