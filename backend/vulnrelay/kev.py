"""CISA KEV catalog ingestion; a successful download is an authoritative snapshot."""

import json
import re
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_catalog(payload: object) -> tuple[str, list[dict]]:
    if not isinstance(payload, dict):
        raise TypeError("Invalid KEV catalog")
    released = datetime.fromisoformat(payload["dateReleased"])
    if released.tzinfo is None:
        raise ValueError("Catalog timestamp has no timezone")
    released_at = released.astimezone(UTC).isoformat()
    records = payload["vulnerabilities"]
    if not isinstance(records, list) or not records or payload["count"] != len(records):
        raise ValueError("Incomplete KEV catalog")
    entries = []
    seen = set()
    for record in records:
        cve_id = record["cveID"]
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("Invalid CVE identifier")
        if cve_id in seen:
            raise ValueError("Duplicate KEV identifier")
        seen.add(cve_id)
        date_added = record["dateAdded"]
        date.fromisoformat(date_added)
        entries.append({"id": cve_id, "date_added": date_added,
                        "raw": json.dumps(record, ensure_ascii=False, sort_keys=True)})
    return released_at, entries


def sync(engine: Engine, *, client: httpx.Client | None = None) -> int:
    """Replace KEV snapshot atomically; failure retains the last valid catalog."""
    owned_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    try:
        response = client.get(URL)
        response.raise_for_status()
        released, entries = parse_catalog(response.json())
        with engine.begin() as connection:
            previous = connection.execute(text("SELECT checkpoint FROM source_state WHERE source='cisa_kev'")).scalar_one_or_none()
            if previous and datetime.fromisoformat(released) < datetime.fromisoformat(previous):
                raise ValueError("Refusing an older KEV catalog")
            connection.execute(text("DELETE FROM kev_entries"))
            connection.execute(text("INSERT INTO kev_entries (cve_id, date_added, raw) VALUES (:id, :date_added, :raw)"), entries)
            connection.execute(text('''INSERT INTO source_state (source, checkpoint, last_success_at, last_error)
                VALUES ('cisa_kev', :checkpoint, :success, NULL)
                ON CONFLICT(source) DO UPDATE SET checkpoint=excluded.checkpoint,
                last_success_at=excluded.last_success_at, last_error=NULL'''),
                {"checkpoint": released, "success": datetime.now(UTC).isoformat()})
        return len(entries)
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        try:
            with engine.begin() as connection:
                connection.execute(text('''INSERT INTO source_state (source, last_error)
                    VALUES ('cisa_kev', 'CISA KEV synchronization failed')
                    ON CONFLICT(source) DO UPDATE SET last_error=excluded.last_error'''))
        except SQLAlchemyError:
            pass
        raise
    finally:
        if owned_client:
            client.close()
