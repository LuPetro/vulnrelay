"""Opt-in OSV package/version lookups with atomic per-asset snapshots."""

import hashlib
import json
import re
import time
from datetime import UTC, datetime

import httpx
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.nvd import retry_after_seconds
from vulnrelay.schemas import Asset
from vulnrelay.store import list_documents

URL = "https://api.osv.dev/v1/query"
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20
MAX_FINDINGS = 2000


class AssetChanged(ValueError):
    """An inventory change invalidated an in-flight OSV lookup."""


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError("Invalid OSV modification time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except ValueError:
        raise ValueError("Invalid OSV modification time") from None


def normalized_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).casefold()
    if ecosystem == "NuGet":
        return name.casefold()
    if ecosystem == "crates.io":
        return name.casefold().replace("_", "-")
    return name


def identity(asset: Asset) -> tuple[str, str, str]:
    return asset.ecosystem, normalized_name(asset.ecosystem, asset.package), asset.version


def _asset_unchanged(connection, asset_id: str, asset: Asset) -> bool:
    latest = connection.execute(
        text("SELECT document FROM assets WHERE id=:asset"), {"asset": asset_id}
    ).scalar_one_or_none()
    if not latest:
        return False
    try:
        current = Asset.model_validate_json(latest)
    except ValueError:
        return False
    return current.enabled and current.kind == "package" and identity(current) == identity(asset)


def failure_message(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        code = error.response.status_code
        reason = (
            "rate limit"
            if code == 429
            else "upstream unavailable"
            if code >= 500
            else "request rejected"
        )
        return f"OSV {reason} (HTTP {code}); previous findings retained"
    if isinstance(error, httpx.TimeoutException):
        return "OSV timed out; previous findings retained"
    if isinstance(error, httpx.HTTPError):
        return "OSV connection failed; previous findings retained"
    return "OSV response was invalid, incomplete, or asset changed; previous findings retained"


def asset_status(engine: Engine) -> list[dict]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text(
                    "SELECT asset_id,last_attempt,last_success,last_error FROM osv_asset_state ORDER BY asset_id"
                )
            ).mappings()
        ]


def _records(client: httpx.Client, asset: Asset) -> list[dict]:
    query = {
        "package": {"name": asset.package, "ecosystem": asset.ecosystem},
        "version": asset.version,
    }
    all_records, seen_tokens = [], set()
    for _ in range(MAX_PAGES):
        with client.stream("POST", URL, json=query, follow_redirects=False) as response:
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_PAGE_BYTES:
                    raise ValueError("OSV page is too large")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
        if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
            raise ValueError("Invalid OSV response")
        all_records.extend(data.get("vulns", []))
        if len(all_records) > MAX_FINDINGS:
            raise ValueError("OSV result exceeds the configured safety limit")
        token = data.get("next_page_token")
        if token is None:
            return all_records
        if not isinstance(token, str) or not token or len(token) > 2000 or token in seen_tokens:
            raise ValueError("Invalid OSV page token")
        seen_tokens.add(token)
        query["page_token"] = token
    raise ValueError("OSV pagination exceeded the safety limit")


def _normalize(record: dict, asset: Asset) -> list[tuple[str, str, dict]]:
    if not isinstance(record, dict):
        raise ValueError("Invalid OSV record")
    osv_id = record.get("id")
    if not isinstance(osv_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", osv_id
    ):
        raise ValueError("Invalid OSV identifier")
    modified = record.get("modified")
    _timestamp(modified)
    if record.get("withdrawn"):
        return []
    affected = record.get("affected", [])
    if not isinstance(affected, list):
        raise ValueError("Invalid OSV affected package information")
    matching_packages = [
        entry
        for entry in affected
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("package"), dict)
            and entry["package"].get("ecosystem") == asset.ecosystem
            and isinstance(entry["package"].get("name"), str)
            and normalized_name(asset.ecosystem, entry["package"]["name"]) == identity(asset)[1]
        )
    ]
    if not matching_packages:
        raise ValueError("OSV response does not identify the requested package")
    aliases = record.get("aliases", [])
    if (
        not isinstance(aliases, list)
        or len(aliases) > 1000
        or any(not isinstance(value, str) or len(value) > 200 for value in aliases)
    ):
        raise ValueError("Invalid OSV aliases")
    ids = {
        value for value in [osv_id, *aliases] if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", value)
    }
    description = record.get("details") or record.get("summary") or ""
    if not isinstance(description, str) or len(description) > 200000:
        raise ValueError("Invalid OSV description")
    # Only public source fields needed for explanation are retained. CVSS is not
    # guessed from vector strings and existing NVD assessments remain untouched.
    # Source timestamps and unrelated metadata do not by themselves justify an
    # alert. Track only content used for notification decisions or fix context.
    ranges, versions = [], []
    for entry in matching_packages:
        selected_ranges, selected_versions = entry.get("ranges", []), entry.get("versions", [])
        if (
            not isinstance(selected_ranges, list)
            or not all(isinstance(item, dict) for item in selected_ranges)
            or not isinstance(selected_versions, list)
            or not all(isinstance(item, str) and len(item) <= 200 for item in selected_versions)
        ):
            raise ValueError("Invalid OSV package ranges or versions")
        ranges.extend(
            json.dumps(item, sort_keys=True, ensure_ascii=True, allow_nan=False)
            for item in selected_ranges
        )
        versions.extend(selected_versions)
    references = record.get("references", [])
    if not isinstance(references, list):
        raise ValueError("Invalid OSV references")
    fix_links = []
    for ref in references:
        if isinstance(ref, dict) and ref.get("type") == "FIX":
            url = ref.get("url")
            if not isinstance(url, str) or len(url) > 2048:
                raise ValueError("Invalid OSV fix reference")
            fix_links.append(url)
    material = json.dumps(
        {
            "description": description,
            "ranges": sorted(set(ranges)),
            "versions": sorted(set(versions)),
            "fix_links": sorted(set(fix_links)),
        },
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    )
    normalized = {
        "id": osv_id,
        "description": description,
        "modified": modified,
        "material_hash": hashlib.sha256(material.encode()).hexdigest(),
    }
    return [(cve_id, osv_id, normalized) for cve_id in ids]


def refresh(
    engine: Engine,
    *,
    client: httpx.Client | None = None,
    now: float | None = None,
    batch_size: int = 20,
) -> dict:
    current = time.time() if now is None else now
    assets = []
    for document in list_documents(engine, "assets"):
        try:
            asset = Asset.model_validate({k: v for k, v in document.items() if k != "id"})
            if asset.enabled and asset.kind == "package":
                assets.append((document["id"], asset))
        except ValidationError:
            continue
    with engine.connect() as connection:
        attempts = {
            row.asset_id: row.last_attempt
            for row in connection.execute(text("SELECT asset_id,last_attempt FROM osv_asset_state"))
        }
    assets.sort(key=lambda item: (attempts.get(item[0], 0), item[0]))
    owned = client is None
    client = client or httpx.Client(
        timeout=httpx.Timeout(15, connect=5), trust_env=False, follow_redirects=False
    )
    succeeded = failed = found = attempted = 0
    retry_after = 0.0
    try:
        for asset_id, asset in assets[: max(1, min(batch_size, 100))]:
            attempted += 1
            try:
                records = _records(client, asset)
                normalized = []
                seen = {}
                for record in records:
                    if isinstance(record, dict) and isinstance(record.get("id"), str):
                        previous = seen.get(record["id"])
                        if previous is not None:
                            if previous != record:
                                raise ValueError("OSV returned conflicting duplicate records")
                            continue
                        seen[record["id"]] = record
                    normalized.extend(_normalize(record, asset))
                with engine.connect() as connection:
                    if engine.dialect.name == "sqlite":
                        # Serialize the final identity check with asset edits.
                        connection.exec_driver_sql("BEGIN IMMEDIATE")
                    if not _asset_unchanged(connection, asset_id, asset):
                        raise AssetChanged("Asset changed during lookup")
                    previous_records = {
                        (row.cve_id, row.osv_id): json.loads(row.record)
                        for row in connection.execute(
                            text(
                                "SELECT cve_id,osv_id,record FROM osv_findings WHERE asset_id=:asset"
                            ),
                            {"asset": asset_id},
                        )
                    }
                    previous_by_id = {}
                    for (_, old_id), previous in previous_records.items():
                        old_time = _timestamp(previous["modified"])
                        if old_id not in previous_by_id or old_time > previous_by_id[old_id]:
                            previous_by_id[old_id] = old_time
                    for source in records:
                        if (
                            isinstance(source, dict)
                            and source.get("id") in previous_by_id
                            and _timestamp(source.get("modified")) < previous_by_id[source["id"]]
                        ):
                            raise ValueError("OSV record is older than the stored snapshot")
                    connection.execute(
                        text("DELETE FROM osv_findings WHERE asset_id=:asset"), {"asset": asset_id}
                    )
                    for cve_id, osv_id, record in normalized:
                        record = dict(record)
                        previous = previous_records.get((cve_id, osv_id))
                        if previous:
                            old_modified = _timestamp(previous["modified"])
                            new_modified = _timestamp(record["modified"])
                            if new_modified < old_modified:
                                raise ValueError("OSV record is older than the stored snapshot")
                            old_hash = previous.get("material_hash")
                            changed = old_hash is not None and old_hash != record["material_hash"]
                            if old_hash is None:
                                changed = previous.get("description") != record["description"]
                            if new_modified == old_modified and changed:
                                raise ValueError(
                                    "OSV content changed without a newer modification time"
                                )
                            unchanged = not changed and (
                                old_hash is not None or new_modified == old_modified
                            )
                            record["alert_revision"] = (
                                previous.get("alert_revision", previous["modified"])
                                if unchanged
                                else record["modified"]
                            )
                        else:
                            record["alert_revision"] = record["modified"]
                        connection.execute(
                            text("""INSERT INTO osv_findings
                        (asset_id,cve_id,osv_id,ecosystem,package,version,record,checked_at)
                        VALUES (:asset,:cve,:osv,:ecosystem,:package,:version,:record,:checked)
                        ON CONFLICT(asset_id,cve_id,osv_id) DO UPDATE SET record=excluded.record,checked_at=excluded.checked_at"""),
                            {
                                "asset": asset_id,
                                "cve": cve_id,
                                "osv": osv_id,
                                "ecosystem": asset.ecosystem,
                                "package": identity(asset)[1],
                                "version": asset.version,
                                "record": json.dumps(record, ensure_ascii=False),
                                "checked": current,
                            },
                        )
                    connection.execute(
                        text("""INSERT INTO osv_asset_state (asset_id,last_attempt,last_success,last_error)
                    VALUES (:asset,:now,:now,NULL) ON CONFLICT(asset_id) DO UPDATE SET
                    last_attempt=:now,last_success=:now,last_error=NULL"""),
                        {"asset": asset_id, "now": current},
                    )
                    connection.commit()
                succeeded += 1
                found += len(normalized)
            except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as error:
                failed += 1
                if not isinstance(error, AssetChanged):
                    with engine.connect() as connection:
                        if engine.dialect.name == "sqlite":
                            connection.exec_driver_sql("BEGIN IMMEDIATE")
                        if _asset_unchanged(connection, asset_id, asset):
                            connection.execute(
                                text("""INSERT INTO osv_asset_state (asset_id,last_attempt,last_error)
                    VALUES (:asset,:now,:error) ON CONFLICT(asset_id) DO UPDATE SET
                    last_attempt=:now,last_error=:error"""),
                                {
                                    "asset": asset_id,
                                    "now": current,
                                    "error": failure_message(error),
                                },
                            )
                        connection.commit()
                if isinstance(error, httpx.HTTPStatusError) and error.response.status_code == 429:
                    retry_after = retry_after_seconds(error.response)
                if isinstance(error, httpx.TransportError) or (
                    isinstance(error, httpx.HTTPStatusError)
                    and (error.response.status_code == 429 or error.response.status_code >= 500)
                ):
                    break  # Avoid one timeout per asset during an upstream outage.
    finally:
        if owned:
            client.close()
    if succeeded or failed:
        stamp = datetime.fromtimestamp(current, UTC).isoformat()
        with engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO source_state (source,last_success_at,last_error)
            VALUES ('osv',:success,:error) ON CONFLICT(source) DO UPDATE SET
            last_success_at=COALESCE(:success,source_state.last_success_at),last_error=:error"""),
                {
                    "success": stamp if succeeded else None,
                    "error": "Some OSV package lookups failed; previous findings retained"
                    if failed
                    else "",
                },
            )
    return {
        "assets_checked": succeeded,
        "assets_failed": failed,
        "cve_findings": found,
        "remaining_assets": max(0, len(assets) - attempted),
        "retry_after": retry_after,
    }
