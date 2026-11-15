"""Correlate stored intelligence, evaluate deterministic rules, and populate a durable outbox."""

import hashlib
import json
import logging
import time
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.matching import match, split_cpe
from vulnrelay.rules import evaluate
from vulnrelay.schemas import Asset, Rule
from vulnrelay.store import get_document, list_documents

logger = logging.getLogger(__name__)


def vulnerabilities(
    engine: Engine,
    cve_id: str | None = None,
    *,
    after: str | None = None,
    page_size: int | None = None,
):
    query = """SELECT ids.id, v.nvd_raw, v.description, v.status, v.cvss_score, v.severity,
               k.raw AS kev_raw, e.score AS epss, e.percentile, e.measured_on,
               o.normalized AS opencve_data,o.checked_at AS opencve_checked_at,o.synced_at AS opencve_synced_at,
               (SELECT checkpoint FROM source_state WHERE source='cisa_kev') AS kev_catalog
               FROM (SELECT id FROM vulnerabilities UNION SELECT cve_id AS id FROM kev_entries
                     UNION SELECT cve_id AS id FROM opencve_records WHERE normalized IS NOT NULL) ids
               LEFT JOIN vulnerabilities v ON v.id=ids.id
               LEFT JOIN kev_entries k ON k.cve_id=ids.id
               LEFT JOIN epss_scores e ON e.cve_id=ids.id
               LEFT JOIN opencve_records o ON o.cve_id=ids.id"""
    conditions, params = [], {}
    if cve_id:
        conditions.append("ids.id=:id")
        params["id"] = cve_id
    if after:
        conditions.append("ids.id>:after")
        params["after"] = after
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY ids.id"
    if page_size:
        query += " LIMIT :page_size"
        params["page_size"] = page_size
    with engine.connect() as connection:
        for row in connection.execute(text(query), params).mappings():
            nvd = json.loads(row["nvd_raw"]) if row["nvd_raw"] else {}
            kev = json.loads(row["kev_raw"]) if row["kev_raw"] else None
            opencve = json.loads(row["opencve_data"]) if row["opencve_data"] else None
            cvss_source = (
                "NVD"
                if row["cvss_score"] is not None
                else "OpenCVE"
                if opencve and opencve["cvss"] is not None
                else None
            )
            sources = (
                (["NVD"] if row["nvd_raw"] else [])
                + (["CISA KEV"] if row["kev_catalog"] or kev else [])
                + (["FIRST EPSS"] if row["epss"] is not None else [])
                + (["OpenCVE"] if opencve else [])
            )
            yield {
                "id": row["id"],
                "nvd": nvd,
                "kev_record": kev,
                "description": row["description"]
                or (kev or {}).get("shortDescription")
                or (opencve or {}).get("description", ""),
                "status": row["status"] or "Unknown",
                "cvss": row["cvss_score"] if cvss_source == "NVD" else (opencve or {}).get("cvss"),
                "severity": row["severity"]
                if cvss_source == "NVD"
                else (opencve or {}).get("severity"),
                "cvss_source": cvss_source,
                "sources": sources,
                "opencve": opencve,
                "opencve_checked_at": row["opencve_checked_at"],
                "opencve_synced_at": row["opencve_synced_at"],
                "epss": row["epss"],
                "percentile": row["percentile"],
                "epss_date": row["measured_on"],
                "kev": True
                if row["kev_raw"] is not None
                else False
                if row["kev_catalog"]
                else None,
                "kev_catalog": row["kev_catalog"],
            }


def _batches(engine: Engine, cve_id: str | None):
    after = None
    while True:
        batch = list(vulnerabilities(engine, cve_id, after=after, page_size=500))
        if not batch:
            return
        yield from batch
        after = batch[-1]["id"]
        if cve_id or len(batch) < 500:
            return


def _event_key(
    rule_id: str,
    asset_id: str,
    destination: str,
    vulnerability: dict,
    evidence: dict,
    changes: bool,
):
    material = {
        "cve": vulnerability["id"],
        "rule": rule_id,
        "asset": asset_id,
        "destination": destination,
    }
    if changes:
        material.update(
            {
                "cvss": vulnerability["cvss"],
                "kev": vulnerability["kev"],
                "epss_band": int(vulnerability["epss"] * 10)
                if vulnerability["epss"] is not None
                else None,
                "status": vulnerability["status"],
                "evidence": evidence,
                "patches": sorted(
                    ref.get("url", "")
                    for ref in vulnerability["nvd"].get("references", [])
                    if "Patch" in ref.get("tags", [])
                ),
            }
        )
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def _evaluate_pair(
    vulnerability: dict,
    asset_id: str,
    asset: Asset,
    rule_id: str,
    rule: Rule,
    *,
    evidence: dict | None = None,
) -> dict | None:
    """The same matching and rule decision is used at enqueue and before delivery."""
    if (rule.assets and asset_id not in rule.assets) or (
        rule.groups and asset.group not in rule.groups
    ):
        return None
    evidence = evidence if evidence is not None else match(asset, vulnerability)
    if not evidence:
        return None
    vendor, product = asset.vendor, asset.product
    if isinstance(evidence["evidence"], dict):
        details = evidence["evidence"]
        if "criteria" in details:
            identity = split_cpe(details["criteria"])
            vendor, product = vendor or identity[3], product or identity[4]
        else:
            vendor, product = vendor or details.get("vendor"), product or details.get("product")
    context = {
        "cvss": vulnerability["cvss"],
        "severity": vulnerability["severity"],
        "epss": vulnerability["epss"],
        "percentile": vulnerability["percentile"],
        "kev": vulnerability["kev"],
        "group": asset.group,
        "exposed": asset.exposed,
        "importance": asset.importance,
        "confidence": evidence["confidence"],
        "vendor": vendor or None,
        "product": product or None,
        "keyword": vulnerability["description"],
        "tags": asset.tags,
    }
    explanation = evaluate(rule.condition, context)
    return {
        "cve_id": vulnerability["id"],
        "asset_id": asset_id,
        "asset": asset.name,
        "rule_id": rule_id,
        "rule": rule.name,
        "match": evidence,
        "evaluation": explanation,
        "matched": explanation["result"] is True,
        "vulnerability": {
            k: v for k, v in vulnerability.items() if k not in ("nvd", "kev_record", "opencve")
        },
        "format": rule.format,
    }


def refresh_alert(
    engine: Engine, payload: dict, destination: str
) -> tuple[dict | None, str | None]:
    """Revalidate queued alerts using current config and intelligence; tests need no rule."""
    if not isinstance(payload, dict):
        return None, "Invalid queued alert"
    if payload.get("test") is True:
        return payload, None
    if not all(isinstance(payload.get(key), str) for key in ("rule_id", "asset_id", "cve_id")):
        return None, "Queued alert is missing its configuration identity"
    rule_row = get_document(engine, "rules", payload["rule_id"])
    if not rule_row or not rule_row.get("enabled", True):
        return None, "Rule disabled or removed"
    asset_row = get_document(engine, "assets", payload["asset_id"])
    if not asset_row or not asset_row.get("enabled", True):
        return None, "Asset disabled or removed"
    try:
        rule = Rule.model_validate({k: v for k, v in rule_row.items() if k != "id"})
        asset = Asset.model_validate({k: v for k, v in asset_row.items() if k != "id"})
    except ValidationError:
        return None, "Asset or rule configuration is invalid; review the current configuration"
    if destination not in rule.destinations:
        return None, "Destination removed from rule"
    vulnerability = next(vulnerabilities(engine, payload["cve_id"]), None)
    if not vulnerability:
        return None, "Vulnerability no longer available"
    refreshed = _evaluate_pair(vulnerability, asset_row["id"], asset, rule_row["id"], rule)
    if not refreshed or not refreshed["matched"]:
        return None, "Current asset, vulnerability or rule no longer matches"
    return refreshed, None


def correlate(
    engine: Engine,
    *,
    enqueue: bool = False,
    rule_id: str | None = None,
    cve_id: str | None = None,
    limit: int = 200,
) -> dict:
    assets = []
    for row in list_documents(engine, "assets"):
        try:
            asset = Asset.model_validate({k: v for k, v in row.items() if k != "id"})
        except ValidationError:
            # An invalid legacy asset must not stop monitoring other assets.
            logger.warning("Skipping invalid asset configuration", extra={"asset_id": row["id"]})
            continue
        assets.append((row["id"], asset))
    rules = [
        (row["id"], Rule.model_validate({k: v for k, v in row.items() if k != "id"}))
        for row in list_documents(engine, "rules")
        if not rule_id or row["id"] == rule_id
    ]
    destinations = {row["id"] for row in list_documents(engine, "connectors") if row["enabled"]}
    reports, count, queued = [], 0, 0
    if (
        not any(asset.enabled for _, asset in assets)
        or not rules
        or (enqueue and not any(rule.enabled for _, rule in rules))
    ):
        return {"evaluations": 0, "queued": 0, "reports": [], "truncated": False}
    # Each bounded page closes its read connection before queue writes begin.
    for vulnerability in _batches(engine, cve_id):
        for asset_id, asset in assets:
            evidence = match(asset, vulnerability)
            if not evidence:
                continue
            for current_rule_id, rule in rules:
                if enqueue and not rule.enabled:
                    continue
                payload = _evaluate_pair(
                    vulnerability, asset_id, asset, current_rule_id, rule, evidence=evidence
                )
                if payload is None:
                    continue
                report = {k: v for k, v in payload.items() if k not in ("vulnerability", "format")}
                if len(reports) < limit:
                    reports.append(report)
                count += 1
                if not enqueue or not payload["matched"]:
                    continue
                with engine.begin() as connection:
                    for destination in set(rule.destinations) & destinations:
                        key = _event_key(
                            current_rule_id,
                            asset_id,
                            destination,
                            vulnerability,
                            payload["match"],
                            rule.renotify_changes,
                        )
                        result = connection.execute(
                            text("""INSERT INTO outbox
                            (id, event_key, connector_id, payload, state, attempts, available_at, created_at)
                            VALUES (:id, :key, :destination, :payload, 'pending', 0, :now, :now)
                            ON CONFLICT(event_key) DO UPDATE SET
                            payload=excluded.payload, state='pending', attempts=0, failures=0,
                            available_at=excluded.available_at, lease_until=NULL,
                            lease_token=NULL, last_error=NULL
                            WHERE outbox.state='cancelled'"""),
                            {
                                "id": str(uuid4()),
                                "key": key,
                                "destination": destination,
                                "payload": json.dumps(payload, ensure_ascii=False),
                                "now": time.time(),
                            },
                        )
                        queued += result.rowcount
    return {
        "evaluations": count,
        "queued": queued,
        "reports": reports,
        "truncated": count > len(reports),
    }
