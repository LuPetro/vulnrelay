"""Correlate stored intelligence, evaluate deterministic rules, and populate a durable outbox."""

import hashlib
import json
import time
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.matching import match, split_cpe
from vulnrelay.rules import evaluate
from vulnrelay.schemas import Asset, Rule
from vulnrelay.store import list_documents


def vulnerabilities(engine: Engine, cve_id: str | None = None):
    query = """SELECT ids.id, v.nvd_raw, v.description, v.status, v.cvss_score, v.severity,
               k.raw AS kev_raw, e.score AS epss, e.percentile, e.measured_on,
               (SELECT checkpoint FROM source_state WHERE source='cisa_kev') AS kev_catalog
               FROM (SELECT id FROM vulnerabilities UNION SELECT cve_id AS id FROM kev_entries) ids
               LEFT JOIN vulnerabilities v ON v.id=ids.id
               LEFT JOIN kev_entries k ON k.cve_id=ids.id
               LEFT JOIN epss_scores e ON e.cve_id=ids.id"""
    if cve_id:
        query += " WHERE ids.id=:id"
    query += " ORDER BY ids.id"
    with engine.connect() as connection:
        for row in connection.execute(text(query), {"id": cve_id}).mappings():
            nvd = json.loads(row["nvd_raw"]) if row["nvd_raw"] else {}
            kev = json.loads(row["kev_raw"]) if row["kev_raw"] else None
            yield {"id": row["id"], "nvd": nvd, "kev_record": kev,
                   "description": row["description"] or (kev or {}).get("shortDescription", ""),
                   "status": row["status"] or "Unknown", "cvss": row["cvss_score"],
                   "severity": row["severity"], "epss": row["epss"], "percentile": row["percentile"],
                   "epss_date": row["measured_on"], "kev": True if row["kev_raw"] is not None else False if row["kev_catalog"] else None,
                   "kev_catalog": row["kev_catalog"]}


def _event_key(rule_id: str, asset_id: str, destination: str, vulnerability: dict, evidence: dict, changes: bool):
    material = {"cve": vulnerability["id"], "rule": rule_id, "asset": asset_id, "destination": destination}
    if changes:
        material.update({"cvss": vulnerability["cvss"], "kev": vulnerability["kev"],
                         "epss_band": int(vulnerability["epss"] * 10) if vulnerability["epss"] is not None else None,
                         "status": vulnerability["status"], "evidence": evidence,
                         "patches": sorted(ref.get("url", "") for ref in vulnerability["nvd"].get("references", []) if "Patch" in ref.get("tags", []))})
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def correlate(engine: Engine, *, enqueue: bool = False, rule_id: str | None = None,
              cve_id: str | None = None, limit: int = 200) -> dict:
    assets = [(row["id"], Asset.model_validate({k: v for k, v in row.items() if k != "id"})) for row in list_documents(engine, "assets")]
    rules = [(row["id"], Rule.model_validate({k: v for k, v in row.items() if k != "id"})) for row in list_documents(engine, "rules") if not rule_id or row["id"] == rule_id]
    destinations = {row["id"] for row in list_documents(engine, "connectors") if row["enabled"]}
    reports, count, queued = [], 0, 0
    # Release the source read connection before inserting into the same SQLite database.
    records = list(vulnerabilities(engine, cve_id))
    for vulnerability in records:
        for asset_id, asset in assets:
            evidence = match(asset, vulnerability)
            if not evidence:
                continue
            vendor, product = asset.vendor, asset.product
            if isinstance(evidence["evidence"], dict):
                details = evidence["evidence"]
                if "criteria" in details:
                    identity = split_cpe(details["criteria"])
                    vendor, product = vendor or identity[3], product or identity[4]
                else:
                    vendor, product = vendor or details.get("vendor"), product or details.get("product")
            context = {"cvss": vulnerability["cvss"], "severity": vulnerability["severity"],
                       "epss": vulnerability["epss"], "percentile": vulnerability["percentile"],
                       "kev": vulnerability["kev"], "group": asset.group, "exposed": asset.exposed,
                       "importance": asset.importance, "confidence": evidence["confidence"],
                       "vendor": vendor or None, "product": product or None,
                       "keyword": vulnerability["description"], "tags": asset.tags}
            for current_rule_id, rule in rules:
                if (enqueue and not rule.enabled) or (rule.assets and asset_id not in rule.assets) or (rule.groups and asset.group not in rule.groups):
                    continue
                explanation = evaluate(rule.condition, context)
                report = {"cve_id": vulnerability["id"], "asset_id": asset_id, "asset": asset.name,
                          "rule_id": current_rule_id, "rule": rule.name, "match": evidence,
                          "evaluation": explanation, "matched": explanation["result"] is True}
                if len(reports) < limit:
                    reports.append(report)
                count += 1
                if not enqueue or explanation["result"] is not True:
                    continue
                payload = {**report, "vulnerability": {k: v for k, v in vulnerability.items() if k not in ("nvd", "kev_record")}, "format": rule.format}
                with engine.begin() as connection:
                    for destination in set(rule.destinations) & destinations:
                        key = _event_key(current_rule_id, asset_id, destination, vulnerability, evidence, rule.renotify_changes)
                        result = connection.execute(text('''INSERT INTO outbox
                            (id, event_key, connector_id, payload, state, attempts, available_at, created_at)
                            VALUES (:id, :key, :destination, :payload, 'pending', 0, :now, :now)
                            ON CONFLICT(event_key) DO NOTHING'''),
                            {"id": str(uuid4()), "key": key, "destination": destination,
                             "payload": json.dumps(payload, ensure_ascii=False), "now": time.time()})
                        queued += result.rowcount
    return {"evaluations": count, "queued": queued, "reports": reports, "truncated": count > len(reports)}
