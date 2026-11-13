"""Optional, account-free OpenCVE Knowledge Base lookups with independent provenance."""

import json
import math
import re
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine

MAX_BYTES = 4 * 1024 * 1024


def retry_delay(response: httpx.Response, attempt: int = 0) -> float:
    value = response.headers.get("Retry-After")
    try:
        delay = float(value) if value is not None else 2**attempt
    except ValueError:
        try:
            delay = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return 2**attempt
    return max(0, delay) if math.isfinite(delay) else 2**attempt


def validate_id(cve_id: str) -> str:
    value = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", value):
        raise ValueError("Invalid CVE identifier")
    return value


def record_url(cve_id: str, *, raw: bool = False) -> str:
    cve_id = validate_id(cve_id)
    prefix = (
        "https://raw.githubusercontent.com/opencve/opencve-kb/main"
        if raw
        else ("https://github.com/opencve/opencve-kb/blob/main")
    )
    return f"{prefix}/{cve_id[4:8]}/{cve_id}.json"


def _timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("OpenCVE timestamp needs a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


def _strings(value: object, maximum: int = 20000) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) or len(item) > 10000 for item in value)
    ):
        raise ValueError("Invalid OpenCVE list")
    return value


def normalize(payload: dict, cve_id: str) -> dict:
    """Flat KB CPEs do not retain NVD applicability logic and never confirm versions."""
    if not isinstance(payload, dict) or payload.get("cve") != cve_id:
        raise ValueError("Unexpected OpenCVE record")
    merged = payload["opencve"]
    description = merged["description"]["data"]
    if not isinstance(description, str) or len(description) > 200000:
        raise ValueError("Invalid OpenCVE description")
    modified = _timestamp(merged["updated"]["data"])
    created = _timestamp(merged["created"]["data"])
    metrics = merged.get("metrics", {})
    if not isinstance(metrics, dict):
        raise ValueError("Invalid OpenCVE metrics")
    scores = []
    for key, version in (
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    ):
        assessment = metrics.get(key, {})
        data = assessment.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("Invalid OpenCVE CVSS assessment")
        score = data.get("score")
        if score is None:
            continue
        if type(score) not in (int, float) or not 0 <= score <= 10:
            raise ValueError("Invalid OpenCVE CVSS score")
        scores.append(
            {
                "score": score,
                "version": version,
                "provider": assessment.get("provider"),
                "vector": data.get("vector"),
            }
        )
    score = scores[0]["score"] if scores else None
    version = scores[0]["version"] if scores else None
    severity = (
        None
        if score is None
        else (
            "HIGH"
            if version == "2.0" and score >= 7
            else "CRITICAL"
            if score >= 9
            else "HIGH"
            if score >= 7
            else "MEDIUM"
            if score >= 4
            else "LOW"
            if score > 0 or version == "2.0"
            else "NONE"
        )
    )
    vendors = []
    for value in _strings(merged.get("vendors", {}).get("data", [])):
        vendor, separator, product = value.partition("$PRODUCT$")
        if vendor and (not separator or product):
            vendors.append({"vendor": vendor, "product": product if separator else None})
    return {
        "id": cve_id,
        "description": description,
        "published": created,
        "modified": modified,
        "cvss": score,
        "cvss_version": version,
        "severity": severity,
        "assessments": scores,
        "vendors": vendors,
        "cpes": _strings(merged.get("cpes", {}).get("data", [])),
        "references": _strings(merged.get("references", {}).get("data", [])),
        "weaknesses": _strings(merged.get("weaknesses", {}).get("data", [])),
        "source_url": record_url(cve_id),
        "description_provider": merged["description"].get("provider"),
    }


def _health(engine: Engine, *, success: bool, checkpoint: str | None = None):
    with engine.begin() as connection:
        if success:
            connection.execute(
                text("""INSERT INTO source_state (source,checkpoint,last_success_at,last_error)
                VALUES ('opencve',:checkpoint,:now,NULL) ON CONFLICT(source) DO UPDATE SET
                checkpoint=excluded.checkpoint,last_success_at=excluded.last_success_at,last_error=NULL"""),
                {"checkpoint": checkpoint, "now": datetime.now(UTC).isoformat()},
            )
        else:
            connection.execute(
                text("""INSERT INTO source_state (source,last_error)
                VALUES ('opencve','OpenCVE lookup failed') ON CONFLICT(source) DO UPDATE SET
                last_error=excluded.last_error""")
            )


def lookup(
    engine: Engine, cve_id: str, *, client: httpx.Client | None = None, sleeper=time.sleep
) -> dict | None:
    cve_id = validate_id(cve_id)
    with engine.connect() as connection:
        previous = (
            connection.execute(
                text("SELECT * FROM opencve_records WHERE cve_id=:id"), {"id": cve_id}
            )
            .mappings()
            .one_or_none()
        )
    headers = {
        "Accept": "application/json",
        "User-Agent": "VulnRelay/0.1 (optional OpenCVE KB source)",
    }
    if previous and previous["etag"]:
        headers["If-None-Match"] = previous["etag"]
    owned = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)
    try:
        for attempt in range(3):
            try:
                with client.stream(
                    "GET", record_url(cve_id, raw=True), headers=headers, follow_redirects=False
                ) as response:
                    if response.status_code == 429 or response.status_code >= 500:
                        delay = retry_delay(response, attempt)
                        # Long upstream cooldowns belong in the persisted monitor schedule.
                        if attempt == 2 or delay > 30:
                            response.raise_for_status()
                        sleeper(delay)
                        continue
                    now = datetime.now(UTC).isoformat(timespec="microseconds")
                    if response.status_code in (304, 404):
                        if response.status_code == 304 and (
                            not previous or not previous["normalized"]
                        ):
                            raise ValueError("OpenCVE returned 304 without a cached record")
                        with engine.begin() as connection:
                            connection.execute(
                                text("""INSERT INTO opencve_records (cve_id,checked_at)
                                VALUES (:id,:now) ON CONFLICT(cve_id) DO UPDATE SET checked_at=excluded.checked_at"""),
                                {"id": cve_id, "now": now},
                            )
                        result = (
                            json.loads(previous["normalized"])
                            if response.status_code == 304
                            else None
                        )
                        break
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes(chunk_size=65536):
                        content.extend(chunk)
                        if len(content) > MAX_BYTES:
                            raise ValueError("OpenCVE record exceeds the size limit")
                    raw = json.loads(content)
                    result = normalize(raw, cve_id)
                    if (
                        previous
                        and previous["modified"]
                        and result["modified"] < previous["modified"]
                    ):
                        raise ValueError("Refusing an older OpenCVE record")
                    etag = response.headers.get("ETag")
                    if etag and (len(etag) > 256 or "\n" in etag or "\r" in etag):
                        raise ValueError("Invalid OpenCVE cache tag")
                    with engine.begin() as connection:
                        connection.execute(
                            text("""INSERT INTO opencve_records
                            (cve_id,modified,normalized,raw,etag,checked_at,synced_at)
                            VALUES (:id,:modified,:normalized,:raw,:etag,:now,:now)
                            ON CONFLICT(cve_id) DO UPDATE SET modified=excluded.modified,
                            normalized=excluded.normalized,raw=excluded.raw,etag=excluded.etag,
                            checked_at=excluded.checked_at,synced_at=excluded.synced_at
                            WHERE opencve_records.modified IS NULL OR excluded.modified>=opencve_records.modified"""),
                            {
                                "id": cve_id,
                                "modified": result["modified"],
                                "normalized": json.dumps(result),
                                "raw": json.dumps(raw),
                                "etag": etag,
                                "now": now,
                            },
                        )
                    break
            except httpx.TransportError:
                if attempt == 2:
                    raise
                sleeper(2**attempt)
        if result is not None:
            with engine.connect() as connection:
                result = json.loads(
                    connection.execute(
                        text("SELECT normalized FROM opencve_records WHERE cve_id=:id"),
                        {"id": cve_id},
                    ).scalar_one()
                )
        _health(engine, success=True, checkpoint=cve_id)
        return result
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
        _health(engine, success=False)
        raise
    finally:
        if owned:
            client.close()


def refresh(
    engine: Engine, *, batch_size: int = 25, client: httpx.Client | None = None, sleeper=time.sleep
) -> dict:
    """Refresh bounded local CVEs, caching misses so they cannot starve other records."""
    if not 1 <= batch_size <= 100:
        raise ValueError("OpenCVE batch size must be between 1 and 100")
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat(timespec="microseconds")
    with engine.connect() as connection:
        ids = (
            connection.execute(
                text("""SELECT ids.id FROM
            (SELECT id FROM vulnerabilities UNION SELECT cve_id FROM kev_entries
             UNION SELECT cve_id FROM opencve_records WHERE normalized IS NOT NULL) ids
            LEFT JOIN opencve_records o ON o.cve_id=ids.id
            WHERE o.checked_at IS NULL OR o.checked_at<:cutoff
            ORDER BY COALESCE(o.checked_at,''),ids.id DESC LIMIT :limit"""),
                {"cutoff": cutoff, "limit": batch_size},
            )
            .scalars()
            .all()
        )
    found = failed = 0
    for cve_id in ids:
        try:
            found += lookup(engine, cve_id, client=client, sleeper=sleeper) is not None
        except httpx.HTTPError:
            # Stop the batch on transport/rate-limit/server failures rather than hammering the host.
            raise
        except (ValueError, TypeError, KeyError, AttributeError):
            failed += 1
    if failed:
        _health(engine, success=False)
        raise ValueError("One or more OpenCVE lookups failed")
    return {"checked": len(ids), "found": found}
