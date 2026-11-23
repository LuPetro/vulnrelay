"""Opt-in OSV package/version lookups with atomic per-asset snapshots."""

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
from vulnrelay.store import get_document, list_documents

URL = "https://api.osv.dev/v1/query"
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20
MAX_FINDINGS = 2000


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
    if record.get("withdrawn"):
        return []
    affected = record.get("affected", [])
    if not isinstance(affected, list):
        raise ValueError("Invalid OSV affected package information")
    matching_package = any(
        isinstance(entry, dict)
        and isinstance(entry.get("package"), dict)
        and entry["package"].get("ecosystem") == asset.ecosystem
        and isinstance(entry["package"].get("name"), str)
        and normalized_name(asset.ecosystem, entry["package"]["name"]) == identity(asset)[1]
        for entry in affected
    )
    if not matching_package:
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
    modified = record.get("modified")
    if not isinstance(modified, str) or len(modified) > 80:
        raise ValueError("Invalid OSV modification time")
    try:
        if datetime.fromisoformat(modified.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError
    except ValueError:
        raise ValueError("Invalid OSV modification time") from None
    # Only public source fields needed for explanation are retained. CVSS is not
    # guessed from vector strings and existing NVD assessments remain untouched.
    normalized = {"id": osv_id, "description": description, "modified": modified}
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
                latest = get_document(engine, "assets", asset_id)
                current_asset = (
                    Asset.model_validate({k: v for k, v in latest.items() if k != "id"})
                    if latest
                    else None
                )
                if (
                    not current_asset
                    or not current_asset.enabled
                    or current_asset.kind != "package"
                    or identity(current_asset) != identity(asset)
                ):
                    raise ValueError("Asset changed during lookup")
                with engine.begin() as connection:
                    connection.execute(
                        text("DELETE FROM osv_findings WHERE asset_id=:asset"), {"asset": asset_id}
                    )
                    for cve_id, osv_id, record in normalized:
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
                succeeded += 1
                found += len(normalized)
            except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as error:
                failed += 1
                with engine.begin() as connection:
                    connection.execute(
                        text("""INSERT INTO osv_asset_state (asset_id,last_attempt,last_error)
                    VALUES (:asset,:now,:error) ON CONFLICT(asset_id) DO UPDATE SET
                    last_attempt=:now,last_error=:error"""),
                        {"asset": asset_id, "now": current, "error": failure_message(error)},
                    )
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
