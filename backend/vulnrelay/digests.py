"""Scheduled reports over locally synchronized CVEs, routed through the durable outbox."""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.matching import match
from vulnrelay.schemas import Asset, Rule
from vulnrelay.store import list_documents

SCAN_LIMIT = 1000


class Digest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    scope: Literal["global", "relevant"] = "global"
    frequency: Literal["daily", "weekly"] = "weekly"
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    time: str = Field(default="08:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    weekday: int = Field(default=0, ge=0, le=6)
    destinations: list[str] = Field(min_length=1, max_length=20)
    min_cvss: float = Field(default=0, ge=0, le=10, allow_inf_nan=False)
    item_limit: int = Field(default=10, ge=1, le=20)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Choose a valid IANA timezone") from None
        return value


def _local_slot(date, config: Digest) -> float:
    zone = ZoneInfo(config.timezone)
    hour, minute = map(int, config.time.split(":"))
    naive = datetime.combine(date, datetime.min.time()).replace(hour=hour, minute=minute)
    # Repeated wall times use the first occurrence. A nonexistent time moves to
    # the first real local minute after the gap (including half-hour DST jumps).
    for delta in range(26 * 60 + 1):
        wall = naive + timedelta(minutes=delta)
        candidates = set()
        for fold in (0, 1):
            stamp = wall.replace(tzinfo=zone, fold=fold).timestamp()
            if datetime.fromtimestamp(stamp, zone).replace(tzinfo=None) == wall:
                candidates.add(stamp)
        if candidates:
            return min(candidates)
    raise ValueError("No valid report time in the local transition")


def next_run(config: Digest, after: float) -> float:
    local_date = datetime.fromtimestamp(after, ZoneInfo(config.timezone)).date()
    for day in range(15):
        date = local_date + timedelta(days=day)
        if config.frequency == "weekly" and date.weekday() != config.weekday:
            continue
        slot = _local_slot(date, config)
        if slot > after:
            return slot
    raise ValueError("No report occurrence in the next two weeks")


def period_start(config: Digest, slot: float) -> float:
    date = datetime.fromtimestamp(slot, ZoneInfo(config.timezone)).date()
    return _local_slot(date - timedelta(days=7 if config.frequency == "weekly" else 1), config)


def list_digests(engine: Engine) -> list[dict]:
    with engine.connect() as connection:
        return [
            {"id": row.id, **json.loads(row.document), "next_run": row.next_run}
            for row in connection.execute(
                text("SELECT id,document,next_run FROM digests ORDER BY id")
            )
        ]


def save_digest(engine: Engine, document: dict, digest_id: str | None = None, *, now=None) -> dict:
    config = Digest.model_validate(document)
    connectors = {row["id"] for row in list_documents(engine, "connectors")}
    if set(config.destinations) - connectors:
        raise ValueError("Unknown destination")
    identifier = digest_id or str(uuid4())
    due = next_run(config, time.time() if now is None else now)
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO digests (id,document,next_run) VALUES (:id,:document,:next)
            ON CONFLICT(id) DO UPDATE SET document=excluded.document,next_run=excluded.next_run"""),
            {"id": identifier, "document": config.model_dump_json(), "next": due},
        )
    return {"id": identifier, **config.model_dump(), "next_run": due}


def delete_digest(engine: Engine, digest_id: str) -> bool:
    with engine.begin() as connection:
        return (
            connection.execute(text("DELETE FROM digests WHERE id=:id"), {"id": digest_id}).rowcount
            > 0
        )


def schedule_due(engine: Engine, *, now: float | None = None) -> int:
    current = time.time() if now is None else now
    queued = 0
    with engine.connect() as connection:
        rows = list(
            connection.execute(
                text("SELECT id,document,next_run FROM digests WHERE next_run<=:now"),
                {"now": current},
            )
        )
    for row in rows:
        try:
            config = Digest.model_validate_json(row.document)
            if not config.enabled:
                continue
            # If the service was offline for several periods, produce only the
            # latest completed period rather than flooding a destination.
            due = row.next_run
            if current - due > 370 * 86400:
                due = next_run(config, current - 8 * 86400)
            following = next_run(config, due)
            while following <= current:
                due, following = following, next_run(config, following)
            payload = {
                "digest": True,
                "digest_id": row.id,
                "period_start": period_start(config, due),
                "period_end": due,
            }
            with engine.begin() as connection:
                claim = connection.execute(
                    text(
                        "UPDATE digests SET next_run=:next WHERE id=:id AND next_run=:old AND document=:document"
                    ),
                    {
                        "next": following,
                        "id": row.id,
                        "old": row.next_run,
                        "document": row.document,
                    },
                )
                if claim.rowcount != 1:
                    continue
                for destination in set(config.destinations):
                    key = hashlib.sha256(
                        f"digest:{row.id}:{due}:{destination}".encode()
                    ).hexdigest()
                    result = connection.execute(
                        text("""INSERT INTO outbox
                        (id,event_key,connector_id,payload,state,attempts,available_at,created_at)
                        VALUES (:id,:key,:destination,:payload,'pending',0,:now,:now)
                        ON CONFLICT(event_key) DO NOTHING"""),
                        {
                            "id": str(uuid4()),
                            "key": key,
                            "destination": destination,
                            "payload": json.dumps(payload),
                            "now": current,
                        },
                    )
                    queued += result.rowcount
        except (ValueError, TypeError, OverflowError):
            # Invalid legacy report must not stop synchronization or other reports.
            continue
    return queued


def refresh_digest(
    engine: Engine, payload: dict, destination: str
) -> tuple[dict | None, str | None]:
    from vulnrelay.pipeline import _evaluate_pair, vulnerabilities

    with engine.connect() as connection:
        document = connection.execute(
            text("SELECT document FROM digests WHERE id=:id"), {"id": payload.get("digest_id")}
        ).scalar_one_or_none()
    if not document:
        return None, "Report removed"
    try:
        config = Digest.model_validate_json(document)
        start, end = float(payload["period_start"]), float(payload["period_end"])
        if not 0 <= start < end or end - start > 9 * 86400:
            raise ValueError
    except (ValueError, TypeError, KeyError, OverflowError):
        return None, "Report configuration is invalid"
    if not config.enabled:
        return None, "Report disabled"
    if destination not in config.destinations:
        return None, "Destination removed from report"
    params = {
        "start": datetime.fromtimestamp(start, UTC).strftime("%Y-%m-%dT%H:%M:%S"),
        "end": datetime.fromtimestamp(end, UTC).strftime("%Y-%m-%dT%H:%M:%S"),
        "minimum": config.min_cvss,
        "limit": SCAN_LIMIT,
    }
    # NVD publication times are UTC. Compare whole seconds so optional
    # fractional seconds or a trailing Z do not move an exact boundary.
    where = "substr(published,1,19)>=:start AND substr(published,1,19)<:end AND COALESCE(status,'')!='Rejected' AND (:minimum=0 OR cvss_score>=:minimum)"
    with engine.connect() as connection:
        total = connection.execute(
            text(f"SELECT COUNT(*) FROM vulnerabilities WHERE {where}"), params
        ).scalar_one()
        ids = (
            connection.execute(
                text(
                    f"SELECT id FROM vulnerabilities WHERE {where} ORDER BY published DESC,id DESC LIMIT :limit"
                ),
                params,
            )
            .scalars()
            .all()
        )
        synced = connection.execute(
            text("SELECT last_success_at FROM source_state WHERE source='nvd'")
        ).scalar_one_or_none()
    assets = []
    rules = []
    if config.scope == "relevant":
        for row in list_documents(engine, "assets"):
            try:
                item = Asset.model_validate({k: v for k, v in row.items() if k != "id"})
                if item.enabled:
                    assets.append((row["id"], item))
            except ValueError:
                continue
        for row in list_documents(engine, "rules"):
            try:
                item = Rule.model_validate({k: v for k, v in row.items() if k != "id"})
                if item.enabled:
                    rules.append((row["id"], item))
            except ValueError:
                continue
    entries, scanned = [], 0
    for cve_id in ids:
        scanned += 1
        vulnerability = next(vulnerabilities(engine, cve_id), None)
        if not vulnerability:
            continue
        reason = None
        if config.scope == "relevant":
            for asset_id, asset in assets:
                evidence = match(asset, vulnerability, asset_id=asset_id)
                if evidence:
                    for rule_id, rule in rules:
                        result = _evaluate_pair(
                            vulnerability, asset_id, asset, rule_id, rule, evidence=evidence
                        )
                        if result and result["matched"]:
                            reason = {
                                "asset": asset.name,
                                "rule": rule.name,
                                "confidence": evidence["confidence"],
                                "explanation": evidence["explanation"],
                            }
                            break
                if reason:
                    break
            if not reason:
                continue
        item = {key: vulnerability[key] for key in ("id", "cvss", "severity", "epss", "kev")}
        if reason:
            item["match"] = reason
        entries.append(item)
        if len(entries) >= config.item_limit:
            break
    return {
        **payload,
        "name": config.name,
        "scope": config.scope,
        "entries": entries,
        "scanned": scanned,
        "candidates": total,
        "nvd_synced": str(synced) if synced else None,
    }, None


def preview_digest(engine: Engine, digest_id: str, *, now: float | None = None) -> dict:
    record = next((item for item in list_digests(engine) if item["id"] == digest_id), None)
    if not record:
        raise ValueError("Report not found")
    current = time.time() if now is None else now
    days = 7 if record["frequency"] == "weekly" else 1
    payload = {
        "digest": True,
        "digest_id": digest_id,
        "period_end": current,
        "period_start": current - days * 86400,
    }
    result, error = refresh_digest(engine, payload, record["destinations"][0])
    if error:
        raise ValueError(error)
    return result
