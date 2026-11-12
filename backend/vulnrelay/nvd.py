"""Incremental NVD ingestion with atomic checkpoints and source provenance."""

import json
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


def _timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds")


def normalize(record: dict) -> dict:
    """Keep the full NVD record alongside selected, explicitly NVD-sourced fields."""
    cve = record["cve"]
    cve_id = cve["id"]
    modified = _iso(_timestamp(cve["lastModified"]))
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
    score = severity = version = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key, [])
        if candidates:
            metric = next((item for item in candidates if item.get("type") == "Primary"), candidates[0])
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            version = data.get("version")
            break
    return {"id": cve_id, "modified": modified, "published": cve.get("published"),
            "status": cve.get("vulnStatus"), "description": description, "cvss_score": score,
            "severity": severity, "cvss_version": version,
            "raw": json.dumps(cve, ensure_ascii=False, sort_keys=True)}


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(60.0, max(0.0, float(retry_after)))
        except ValueError:
            try:
                return min(60.0, max(0.0, (parsedate_to_datetime(retry_after) - datetime.now(UTC)).total_seconds()))
            except (ValueError, TypeError, OverflowError):
                pass
    return min(60.0, 2.0 ** attempt)


def _get(client: httpx.Client, params: dict, headers: dict, sleeper) -> dict:
    for attempt in range(4):
        try:
            response = client.get(URL, params=params, headers=headers)
            if (response.status_code == 429 or response.status_code >= 500) and attempt < 3:
                sleeper(_retry_delay(response, attempt))
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError("NVD returned an invalid response")
            return payload
        except httpx.TransportError:
            if attempt == 3:
                raise
            sleeper(min(60.0, 2.0 ** attempt))
    raise RuntimeError("NVD request failed")


def sync(engine: Engine, *, api_key: str = "", days: int = 7,
         client: httpx.Client | None = None, now: datetime | None = None,
         sleeper=time.sleep) -> int:
    """Fetch a bounded modified-date window; advance checkpoint only on complete success."""
    if not 1 <= days <= 120:
        raise ValueError("days must be between 1 and 120")
    end = now or datetime.now(UTC)
    if end.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    with engine.connect() as connection:
        checkpoint = connection.execute(text("SELECT checkpoint FROM source_state WHERE source='nvd'" )).scalar_one_or_none()
    # Overlap guards against boundary precision and delayed upstream updates.
    start = _timestamp(checkpoint) - timedelta(minutes=5) if checkpoint else end - timedelta(days=days)
    if start >= end:
        raise ValueError("NVD checkpoint is in the future")
    # NVD limits date windows to 120 days. Catch up in bounded consecutive windows.
    end = min(end, start + timedelta(days=119))
    headers = {"apiKey": api_key} if api_key else {}
    owned_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    count = 0
    try:
        # Data and cursor commit together; an interrupted page never advances the cursor.
        with engine.begin() as connection:
            index = 0
            while True:
                if index:
                    sleeper(0.7 if api_key else 6.0)
                payload = _get(client, {"lastModStartDate": _iso(start), "lastModEndDate": _iso(end),
                                        "startIndex": index, "resultsPerPage": PAGE_SIZE}, headers, sleeper)
                records = payload["vulnerabilities"]
                total = int(payload["totalResults"])
                if not isinstance(records, list) or int(payload["startIndex"]) != index:
                    raise ValueError("NVD returned an invalid page")
                if not records and index < total:
                    raise ValueError("NVD returned an incomplete page")
                for record in records:
                    item = normalize(record)
                    connection.execute(text('''INSERT INTO vulnerabilities
                        (id, modified, published, status, description, cvss_score, severity, cvss_version, nvd_raw)
                        VALUES (:id, :modified, :published, :status, :description, :cvss_score, :severity, :cvss_version, :raw)
                        ON CONFLICT(id) DO UPDATE SET modified=excluded.modified, published=excluded.published,
                        status=excluded.status, description=excluded.description, cvss_score=excluded.cvss_score,
                        severity=excluded.severity, cvss_version=excluded.cvss_version, nvd_raw=excluded.nvd_raw
                        WHERE excluded.modified >= vulnerabilities.modified'''), item)
                    count += 1
                index += len(records)
                if index >= total:
                    break
            connection.execute(text('''INSERT INTO source_state (source, checkpoint, last_success_at, last_error)
                VALUES ('nvd', :checkpoint, :success, NULL)
                ON CONFLICT(source) DO UPDATE SET checkpoint=excluded.checkpoint,
                last_success_at=excluded.last_success_at, last_error=NULL'''),
                {"checkpoint": _iso(end), "success": datetime.now(UTC)})
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        # Keep the previous successful cursor intact and avoid persisting upstream secrets.
        try:
            with engine.begin() as connection:
                connection.execute(text("""INSERT INTO source_state (source, last_error)
                    VALUES ('nvd', 'NVD synchronization failed')
                    ON CONFLICT(source) DO UPDATE SET last_error=excluded.last_error"""))
        except SQLAlchemyError:
            pass  # A missing schema or unavailable database cannot record its own error.
        raise
    finally:
        if owned_client:
            client.close()
    return count
