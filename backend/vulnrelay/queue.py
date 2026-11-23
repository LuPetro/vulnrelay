"""Queue diagnostics and explicit dismissals; retained event keys prevent immediate refill."""

import hashlib
import time

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.delivery_schedule import next_delivery_at, schedule_allows
from vulnrelay.schemas import Connector
from vulnrelay.store import list_documents


def provider_key(reference: str) -> str:
    return (
        "bot:"
        + hashlib.sha256(
            (reference if isinstance(reference, str) else "invalid-reference").encode()
        ).hexdigest()[:32]
    )


def connector_provider_key(document: dict) -> str:
    """Keep existing Telegram cooldown keys and isolate webhook providers."""
    kind = document.get("kind", "telegram")
    reference = document.get("token_env", "TELEGRAM_BOT_TOKEN")
    if kind != "telegram":
        reference = f"{kind}:{document.get('webhook_env', '')}"
    return provider_key(reference)


def same_destination(first: dict, second: dict) -> bool:
    kind = first.get("kind", "telegram")
    if kind != second.get("kind", "telegram"):
        return False
    if kind != "telegram":
        return first.get("webhook_env") == second.get("webhook_env")
    return (
        first.get("token_env", "TELEGRAM_BOT_TOKEN")
        == second.get("token_env", "TELEGRAM_BOT_TOKEN")
        and str(first.get("chat_id", "")).casefold() == str(second.get("chat_id", "")).casefold()
    )


class ClearQueue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    before: float = Field(gt=0, allow_inf_nan=False)
    connector_id: str | None = Field(default=None, min_length=1, max_length=36)


def queue_status(engine: Engine, *, now: float | None = None) -> dict:
    current = time.time() if now is None else now
    documents = {item["id"]: item for item in list_documents(engine, "connectors")}
    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        counts = {
            row.state: row.count
            for row in connection.execute(
                text("SELECT state, COUNT(*) AS count FROM outbox GROUP BY state")
            )
        }
        groups = (
            connection.execute(
                text("""SELECT connector_id,
            SUM(CASE WHEN state IN ('pending','retry') THEN 1 ELSE 0 END) AS queued,
            SUM(CASE WHEN state IN ('pending','retry') AND available_at<=:now THEN 1 ELSE 0 END) AS due,
            SUM(CASE WHEN state='sending' THEN 1 ELSE 0 END) AS sending,
            SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END) AS failed,
            MIN(CASE WHEN state IN ('pending','retry') THEN available_at END) AS due_at,
            MAX(sent_at) AS last_sent_at
            FROM outbox GROUP BY connector_id"""),
                {"now": current},
            )
            .mappings()
            .all()
        )
        limits = {
            row["id"]: dict(row)
            for row in connection.execute(
                text("SELECT id,available_at,rate_limited_until FROM connector_limits")
            ).mappings()
        }
        errors = {}
        for error in connection.execute(
            text("""SELECT connector_id,last_error FROM (
            SELECT connector_id,last_error,ROW_NUMBER() OVER (
            PARTITION BY connector_id ORDER BY created_at DESC,id DESC) AS rank
            FROM outbox WHERE state IN ('retry','failed') AND last_error IS NOT NULL
            ) latest WHERE rank=1""")
        ).mappings():
            errors.setdefault(error["connector_id"], error["last_error"])
    destinations = []
    for row in groups:
        document = documents.get(row["connector_id"])
        try:
            config = (
                Connector.model_validate({k: v for k, v in document.items() if k != "id"})
                if document
                else None
            )
        except ValidationError:
            config = None
        limit = limits.get(row["connector_id"], {})
        provider = limits.get(connector_provider_key(document), {}) if config else {}
        cooldown = max(limit.get("rate_limited_until", 0), provider.get("rate_limited_until", 0))
        pacing = max(limit.get("available_at", 0), provider.get("available_at", 0))
        enabled = bool(config and config.enabled)
        next_at = max(current, row["due_at"], pacing) if row["queued"] and enabled else None
        outside_schedule = bool(enabled and not schedule_allows(config.delivery_schedule, current))
        schedule_resume = (
            next_delivery_at(config.delivery_schedule, current) if outside_schedule else None
        )
        if next_at is not None:
            next_at = next_delivery_at(config.delivery_schedule, next_at)
        status = (
            "sending"
            if row["sending"]
            else "failed"
            if not row["queued"] and row["failed"]
            else "empty"
            if not row["queued"]
            else "disabled"
            if not enabled
            else "rate_limited"
            if cooldown > current
            else "outside_schedule"
            if outside_schedule
            else "pacing"
            if pacing > current
            else "retry_wait"
            if row["due_at"] > current
            else "ready"
        )
        destinations.append(
            {
                "id": row["connector_id"],
                "name": document["name"] if document else "Removed destination",
                "kind": config.kind if config else None,
                "status": status,
                "queued": row["queued"],
                "sending": row["sending"],
                "failed": row["failed"],
                "last_error": errors.get(row["connector_id"]),
                "ready": row["due"] if status == "ready" else 0,
                "next_attempt_at": next_at if status != "sending" else None,
                "rate_limited_until": cooldown if cooldown > current else None,
                "last_sent_at": row["last_sent_at"],
                "min_interval_seconds": config.min_interval_seconds if config else None,
                "schedule_resume_at": schedule_resume,
                "schedule_timezone": config.delivery_schedule.timezone
                if config and config.delivery_schedule
                else None,
            }
        )
    deadlines = [
        item["next_attempt_at"] for item in destinations if item["next_attempt_at"] is not None
    ]
    sent_times = [item["last_sent_at"] for item in destinations if item["last_sent_at"] is not None]
    return {
        "as_of": current,
        "counts": counts,
        "queued": counts.get("pending", 0) + counts.get("retry", 0),
        "ready": sum(item["ready"] for item in destinations),
        "sending": counts.get("sending", 0),
        "next_attempt_at": min(deadlines) if deadlines else None,
        "last_sent_at": max(sent_times) if sent_times else None,
        "destinations": destinations,
    }


def clear_queue(engine: Engine, selection: ClearQueue) -> dict:
    cutoff = min(selection.before, time.time())
    with engine.begin() as connection:
        result = connection.execute(
            text("""UPDATE outbox SET state='dismissed',
            lease_until=NULL, lease_token=NULL, last_error='Discarded by operator'
            WHERE state IN ('pending','retry') AND created_at<=:cutoff
            AND (:connector IS NULL OR connector_id=:connector)"""),
            {"cutoff": cutoff, "connector": selection.connector_id},
        )
    return {"cleared": result.rowcount, "before": cutoff}
