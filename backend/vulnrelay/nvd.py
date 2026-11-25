"""Incremental NVD ingestion with atomic checkpoints and source provenance."""

import json
import logging
import math
import random
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from tempfile import SpooledTemporaryFile

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
logger = logging.getLogger(__name__)


class CheckpointError(ValueError):
    """The saved synchronization window cannot be used safely."""


def failure_message(error: Exception) -> str:
    """Return allowlisted diagnostics without upstream bodies, URLs or exception text."""
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        reasons = {
            400: "request rejected; check the server clock and synchronization window",
            401: "authentication rejected; check the configured NVD API key",
            403: "access denied; check the API key if configured, request limits and network access",
            429: "request limit reached; wait before retrying",
        }
        reason = reasons.get(status)
        if reason is None:
            if status >= 500:
                reason = "upstream service unavailable; retry later"
            elif 300 <= status < 400:
                reason = "unexpected redirect; check network or proxy configuration"
            else:
                reason = "unexpected HTTP response"
        return f"NVD HTTP {status}: {reason}."
    if isinstance(error, httpx.TimeoutException):
        return "NVD request timed out; check connectivity or retry later."
    if isinstance(error, httpx.ConnectError):
        return "NVD connection failed; check DNS, TLS, proxy and outbound HTTPS access."
    if isinstance(error, httpx.TransportError):
        return "NVD network request failed; check connectivity and proxy configuration."
    if isinstance(error, CheckpointError):
        return "NVD checkpoint is invalid or in the future; check the server clock and saved state."
    if isinstance(error, SQLAlchemyError):
        return "NVD database operation failed; check database access and migrations."
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return "NVD returned an invalid or incomplete response; retry later."
    return "NVD synchronization failed; check source status and application health."


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
            metric = next(
                (item for item in candidates if item.get("type") == "Primary"), candidates[0]
            )
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            version = data.get("version")
            break
    return {
        "id": cve_id,
        "modified": modified,
        "published": cve.get("published"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss_score": score,
        "severity": severity,
        "cvss_version": version,
        "raw": json.dumps(cve, ensure_ascii=False, sort_keys=True),
    }


def retry_after_seconds(response: httpx.Response) -> float:
    """Read a provider deadline without shortening long cooldowns or accepting NaN/inf."""
    value = response.headers.get("Retry-After")
    if not value:
        return 0.0
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return 0.0
    return max(0.0, seconds) if math.isfinite(seconds) else 0.0


def transient_failure(error: Exception) -> bool:
    return isinstance(error, httpx.TransportError) or (
        isinstance(error, httpx.HTTPStatusError)
        and (error.response.status_code == 429 or error.response.status_code >= 500)
    )


def _retry_delay(response: httpx.Response | None, attempt: int) -> float:
    # Six seconds also respects unauthenticated NVD pacing. Jitter separates clients.
    base = 6.0 * 2**attempt
    return max(
        retry_after_seconds(response) if response is not None else 0.0,
        base + random.uniform(0, base / 4),
    )


def _get(client: httpx.Client, params: dict, headers: dict, sleeper) -> dict:
    for attempt in range(4):
        try:
            response = client.get(URL, params=params, headers=headers)
            if (response.status_code == 429 or response.status_code >= 500) and attempt < 3:
                delay = _retry_delay(response, attempt)
                # Persist long cooldowns in the monitor rather than blocking other sources.
                if delay <= 60:
                    sleeper(delay)
                    continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError("NVD returned an invalid response")
            return payload
        except httpx.TransportError:
            if attempt == 3:
                raise
            sleeper(_retry_delay(None, attempt))
    raise RuntimeError("NVD request failed")


def sync(
    engine: Engine,
    *,
    api_key: str = "",
    days: int = 7,
    client: httpx.Client | None = None,
    now: datetime | None = None,
    sleeper=time.sleep,
) -> int:
    """Fetch a bounded modified-date window; advance checkpoint only on complete success."""
    if not 1 <= days <= 120:
        raise ValueError("days must be between 1 and 120")
    end = now or datetime.now(UTC)
    if end.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    headers = {"apiKey": api_key} if api_key else {}
    owned_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    count = 0
    try:
        with engine.connect() as connection:
            checkpoint = connection.execute(
                text("SELECT checkpoint FROM source_state WHERE source='nvd'")
            ).scalar_one_or_none()
        # Overlap guards against boundary precision and delayed upstream updates.
        try:
            start = (
                _timestamp(checkpoint) - timedelta(minutes=5)
                if checkpoint
                else end - timedelta(days=days)
            )
        except (ValueError, TypeError) as error:
            raise CheckpointError from error
        if start >= end:
            raise CheckpointError
        # NVD limits date windows to 120 days. Catch up in bounded consecutive windows.
        end = min(end, start + timedelta(days=119))
        # Stage the complete response before taking the SQLite write lock. Large windows
        # spill to a temporary file instead of occupying memory or blocking configuration.
        with SpooledTemporaryFile(mode="w+t", max_size=1024 * 1024) as staged:
            index = 0
            while True:
                if index:
                    sleeper(0.7 if api_key else 6.0)
                payload = _get(
                    client,
                    {
                        "lastModStartDate": _iso(start),
                        "lastModEndDate": _iso(end),
                        "startIndex": index,
                        "resultsPerPage": PAGE_SIZE,
                    },
                    headers,
                    sleeper,
                )
                records = payload["vulnerabilities"]
                total = int(payload["totalResults"])
                if (
                    not isinstance(records, list)
                    or int(payload["startIndex"]) != index
                    or total < 0
                ):
                    raise ValueError("NVD returned an invalid page")
                if not records and index < total:
                    raise ValueError("NVD returned an incomplete page")
                for record in records:
                    staged.write(json.dumps(normalize(record)) + "\n")
                    count += 1
                index += len(records)
                if index >= total:
                    break
            staged.seek(0)
            with engine.begin() as connection:
                for line in staged:
                    connection.execute(
                        text("""INSERT INTO vulnerabilities
                        (id, modified, published, status, description, cvss_score, severity, cvss_version, nvd_raw)
                        VALUES (:id, :modified, :published, :status, :description, :cvss_score, :severity, :cvss_version, :raw)
                        ON CONFLICT(id) DO UPDATE SET modified=excluded.modified, published=excluded.published,
                        status=excluded.status, description=excluded.description, cvss_score=excluded.cvss_score,
                        severity=excluded.severity, cvss_version=excluded.cvss_version, nvd_raw=excluded.nvd_raw
                        WHERE excluded.modified >= vulnerabilities.modified"""),
                        json.loads(line),
                    )
                connection.execute(
                    text("""INSERT INTO source_state (source, checkpoint, last_success_at, last_error)
                    VALUES ('nvd', :checkpoint, :success, NULL)
                    ON CONFLICT(source) DO UPDATE SET checkpoint=excluded.checkpoint,
                    last_success_at=excluded.last_success_at, last_error=NULL"""),
                    {"checkpoint": _iso(end), "success": datetime.now(UTC).isoformat()},
                )
                connection.execute(
                    text("""INSERT INTO engine_state (name,value) VALUES ('failures_nvd','0')
                    ON CONFLICT(name) DO UPDATE SET value='0'""")
                )
    except (httpx.HTTPError, ValueError, TypeError, KeyError, SQLAlchemyError) as error:
        # Keep the previous successful cursor intact and avoid persisting upstream secrets.
        message = failure_message(error)
        logger.warning(message, extra={"source": "nvd"})
        try:
            with engine.begin() as connection:
                connection.execute(
                    text("""INSERT INTO source_state (source, last_error)
                    VALUES ('nvd', :error)
                    ON CONFLICT(source) DO UPDATE SET last_error=excluded.last_error"""),
                    {"error": message},
                )
        except SQLAlchemyError:
            pass  # A missing schema or unavailable database cannot record its own error.
        raise
    finally:
        if owned_client:
            client.close()
    return count
