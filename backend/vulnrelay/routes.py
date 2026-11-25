"""Local configuration and troubleshooting API."""

from typing import Literal

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import ValidationError
from sqlalchemy import text

from vulnrelay import ai
from vulnrelay.catalog import CatalogSelection, catalog, import_selection
from vulnrelay.config import get_settings
from vulnrelay.delivery import deliver_one, enqueue_test, history, retry_failed
from vulnrelay.digests import delete_digest, list_digests, preview_digest, save_digest
from vulnrelay.monitor import state
from vulnrelay.news import list_news
from vulnrelay.news import save_settings as save_news_settings
from vulnrelay.opencve import lookup as lookup_opencve
from vulnrelay.opencve import validate_id
from vulnrelay.osv import asset_status as osv_asset_status
from vulnrelay.package_import import InvalidPackageURL, PackageSelection, import_packages
from vulnrelay.pipeline import correlate, vulnerabilities
from vulnrelay.queue import ClearQueue, clear_queue, queue_status
from vulnrelay.schemas import Asset
from vulnrelay.store import delete_document, list_documents, save_document

router = APIRouter(prefix="/api")
Collection = Literal["assets", "rules", "connectors"]


@router.get("/news")
def get_news(request: Request):
    return list_news(request.app.state.engine)


@router.put("/news/settings")
def put_news_settings(document: dict, request: Request):
    try:
        return save_news_settings(request.app.state.engine, document).model_dump()
    except ValueError:
        raise HTTPException(422, "Invalid news settings or destination") from None


@router.get("/digests")
def get_digests(request: Request):
    return list_digests(request.app.state.engine)


@router.post("/digests", status_code=201)
def create_digest(document: dict, request: Request):
    try:
        return save_digest(request.app.state.engine, document)
    except ValueError:
        raise HTTPException(422, "Invalid report settings or destination") from None


@router.put("/digests/{digest_id}")
def update_digest(digest_id: str, document: dict, request: Request):
    if digest_id not in {item["id"] for item in list_digests(request.app.state.engine)}:
        raise HTTPException(404, "Report not found")
    try:
        return save_digest(request.app.state.engine, document, digest_id)
    except ValueError:
        raise HTTPException(422, "Invalid report settings or destination") from None


@router.delete("/digests/{digest_id}")
def remove_digest(digest_id: str, request: Request):
    if not delete_digest(request.app.state.engine, digest_id):
        raise HTTPException(404, "Report not found")
    return {"deleted": True}


@router.post("/digests/{digest_id}/preview")
def get_digest_preview(digest_id: str, request: Request):
    try:
        return preview_digest(request.app.state.engine, digest_id)
    except ValueError:
        raise HTTPException(409, "Report is disabled, invalid, or missing") from None


@router.get("/ai/settings")
def get_ai_settings(request: Request):
    return {
        "settings": ai.settings(request.app.state.engine).model_dump(),
        "usage": ai.usage(request.app.state.engine),
        "custom_endpoint_configured": bool(get_settings().ai_base_url),
        "private_hosts_allowed": get_settings().ai_allow_private_hosts,
    }


@router.put("/ai/settings")
def put_ai_settings(document: dict, request: Request):
    try:
        config = ai.AISettings.model_validate(document)
    except ValidationError:
        raise HTTPException(422, "Invalid AI settings; check model, provider, and limits") from None
    ai.save_settings(request.app.state.engine, config)
    return {"settings": config.model_dump(), "usage": ai.usage(request.app.state.engine)}


@router.post("/ai/test")
def test_ai_connection(request: Request):
    try:
        answer = ai.summarize(
            request.app.state.engine,
            {
                "id": "TEST",
                "description": "Example software has a fictional input validation issue.",
            },
            test=True,
        )
        return {"ok": True, "summary": answer, "usage": ai.usage(request.app.state.engine)}
    except ai.AIError as error:
        return {"ok": False, "message": str(error), "usage": ai.usage(request.app.state.engine)}


@router.get("/catalog")
def get_catalog(q: str = Query("", max_length=200)):
    return catalog(q)


@router.get("/sources/osv/status")
def get_osv_asset_status(request: Request):
    return osv_asset_status(request.app.state.engine)


@router.post("/assets/parse-purl")
def parse_package_url(document: dict):
    try:
        if set(document) != {"purl"}:
            raise ValueError("Invalid package URL request")
        asset = Asset.model_validate({"name": "Preview", "kind": "package", **document})
        return {"ecosystem": asset.ecosystem, "package": asset.package, "version": asset.version}
    except ValueError:
        raise HTTPException(
            422,
            "Unsupported package URL: use npm, PyPI, Go, Maven, Cargo or NuGet with an exact version and no qualifiers or subpath",
        ) from None


@router.post("/packages/{operation}")
def apply_package_selection(
    operation: Literal["preview", "import"], document: dict, request: Request
):
    try:
        return import_packages(
            request.app.state.engine,
            PackageSelection.model_validate(document),
            preview=operation == "preview",
        )
    except InvalidPackageURL as error:
        raise HTTPException(
            422,
            f"Package URL {error.index} is invalid or unsupported; use an exact-version unqualified PURL",
        ) from None
    except ValueError:
        raise HTTPException(422, "Invalid package selection or asset context") from None


@router.post("/catalog/{operation}")
def apply_catalog(operation: Literal["preview", "import"], document: dict, request: Request):
    try:
        selection = CatalogSelection.model_validate(document)
        return import_selection(request.app.state.engine, selection, preview=operation == "preview")
    except ValueError:
        raise HTTPException(422, "Choose known catalog products and valid asset context") from None


def _configuration_error(error: ValueError) -> str:
    # Only expose reviewed static messages, never validation inputs or credentials.
    if isinstance(error, ValidationError) and any(
        item["type"] == "cpe_version_conflict"
        for item in error.errors(include_input=False, include_context=False)
    ):
        return "Inventory version conflicts with the version in the CPE"
    if isinstance(error, ValidationError):
        schedule_errors = [
            item
            for item in error.errors(include_input=False, include_context=False)
            if item["loc"] and item["loc"][0] == "delivery_schedule"
        ]
        if any("timezone" in item["loc"] for item in schedule_errors):
            return "Choose a valid IANA time zone, for example Europe/Vienna"
        if schedule_errors:
            return "Invalid delivery hours: choose weekdays and different start/end times in HH:MM"
    return "Invalid configuration or missing asset/connector reference"


@router.get("/overview")
def overview(request: Request):
    engine = request.app.state.engine
    with engine.connect() as connection:
        sources = [
            dict(row)
            for row in connection.execute(
                text(
                    "SELECT source, checkpoint, last_success_at, last_error FROM source_state ORDER BY source"
                )
            ).mappings()
        ]
        counts = {
            table: connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
            for table in ("assets", "rules", "connectors", "vulnerabilities")
        }
    schedule = state(engine)
    for source in sources:
        source_id = source["source"]
        source["next_attempt_at"] = schedule.get(f"next_{source_id}")
        source["last_attempt_at"] = schedule.get(f"last_attempt_{source_id}")
        source["retry_scheduled"] = bool(
            source["last_error"] and schedule.get(f"failures_{source_id}", 0)
        )
    queue = queue_status(engine)
    return {
        "counts": counts,
        "sources": sources,
        "deliveries": queue["counts"],
        "queue": queue,
        "engine": schedule,
        "setup_required": not all(counts[key] for key in ("assets", "rules", "connectors")),
        "opencve_enabled": get_settings().opencve_enabled,
        "osv_enabled": get_settings().osv_enabled,
    }


@router.get("/config/{collection}")
def list_config(collection: Collection, request: Request):
    return list_documents(request.app.state.engine, collection)


@router.post("/config/{collection}", status_code=201)
def create_config(collection: Collection, document: dict, request: Request):
    try:
        return save_document(request.app.state.engine, collection, document)
    except ValueError as error:
        raise HTTPException(422, _configuration_error(error)) from None


@router.put("/config/{collection}/{document_id}")
def update_config(collection: Collection, document_id: str, document: dict, request: Request):
    if document_id not in {
        row["id"] for row in list_documents(request.app.state.engine, collection)
    }:
        raise HTTPException(404, "Configuration entry not found")
    try:
        return save_document(request.app.state.engine, collection, document, document_id)
    except ValueError as error:
        raise HTTPException(422, _configuration_error(error)) from None


@router.delete("/config/{collection}/{document_id}")
def delete_config(collection: Collection, document_id: str, request: Request):
    if not delete_document(request.app.state.engine, collection, document_id):
        raise HTTPException(404, "Configuration entry not found")
    return {"deleted": True}


@router.get("/evaluate")
def evaluate_rules(request: Request, rule_id: str | None = None, cve_id: str | None = None):
    return correlate(request.app.state.engine, rule_id=rule_id, cve_id=cve_id)


@router.post("/queue/evaluate")
def queue_matches(request: Request):
    return correlate(request.app.state.engine, enqueue=True)


@router.post("/connectors/{connector_id}/test", status_code=202)
def test_connector(connector_id: str, request: Request):
    try:
        return {"queued": enqueue_test(request.app.state.engine, connector_id)}
    except ValueError:
        raise HTTPException(404, "Connector not found") from None


@router.get("/deliveries")
def deliveries(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    state: Literal["pending", "retry", "sending", "sent", "failed", "cancelled", "dismissed"]
    | None = None,
):
    return history(request.app.state.engine, limit, state)


@router.get("/queue/status")
def get_queue_status(request: Request):
    return queue_status(request.app.state.engine)


@router.post("/queue/clear")
def clear_waiting_queue(selection: ClearQueue, request: Request):
    return clear_queue(request.app.state.engine, selection)


@router.post("/deliveries/next")
def next_delivery(request: Request):
    return deliver_one(request.app.state.engine)


@router.get("/vulnerabilities")
def list_vulnerabilities(
    request: Request, q: str = Query("", max_length=200), limit: int = Query(50, ge=1, le=200)
):
    result = []
    for entry in vulnerabilities(request.app.state.engine):
        if q and q.casefold() not in (entry["id"] + " " + entry["description"]).casefold():
            continue
        result.append(
            {k: v for k, v in entry.items() if k not in ("nvd", "kev_record", "opencve", "osv")}
        )
        if len(result) >= limit:
            break
    return result


@router.get("/vulnerabilities/{cve_id}")
def vulnerability_details(cve_id: str, request: Request):
    records = list(vulnerabilities(request.app.state.engine, cve_id.upper()))
    if not records:
        raise HTTPException(404, "CVE not found locally")
    return {
        "vulnerability": records[0],
        "matches": correlate(request.app.state.engine, cve_id=cve_id.upper()),
    }


@router.post("/sources/opencve/{cve_id}/lookup")
def lookup_opencve_record(cve_id: str, request: Request):
    try:
        cve_id = validate_id(cve_id)
    except ValueError:
        raise HTTPException(422, "Invalid CVE identifier") from None
    try:
        result = lookup_opencve(request.app.state.engine, cve_id)
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(502, "OpenCVE lookup failed; existing data was preserved") from None
    return {"found": result is not None, "record": result}


@router.post("/deliveries/{message_id}/retry")
def retry_delivery(message_id: str, request: Request):
    if not retry_failed(request.app.state.engine, message_id):
        raise HTTPException(409, "Delivery does not exist or is not in failed state")
    return {"retrying": message_id}
