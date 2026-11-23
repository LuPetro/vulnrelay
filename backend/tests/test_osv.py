import json
import time

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from typer.testing import CliRunner
from vulnrelay import cli, osv
from vulnrelay.api import app
from vulnrelay.delivery import deliver_one
from vulnrelay.matching import match
from vulnrelay.pipeline import correlate, vulnerabilities
from vulnrelay.schemas import Asset
from vulnrelay.store import delete_document, save_document


def package(engine, **overrides):
    return save_document(
        engine,
        "assets",
        {
            "name": "App dependency",
            "kind": "package",
            "ecosystem": "npm",
            "package": "next",
            "version": "15.1.0",
            "group": "app",
            **overrides,
        },
    )


def advisory(identifier="GHSA-example-1234", aliases=None, ecosystem="npm", name="next", **extra):
    return {
        "id": identifier,
        "aliases": aliases if aliases is not None else ["CVE-2026-1234"],
        "modified": "2026-11-20T12:00:00Z",
        "summary": "Public package issue",
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}}],
        **extra,
    }


def test_exact_package_flows_from_osv_to_explainable_alert(configured_engine, monkeypatch):
    asset = package(configured_engine)
    connector = save_document(
        configured_engine, "connectors", {"name": "Channel", "chat_id": "-123"}
    )
    save_document(
        configured_engine,
        "rules",
        {
            "name": "Exact dependency",
            "destinations": [connector["id"]],
            "condition": {
                "kind": "condition",
                "field": "confidence",
                "op": "eq",
                "value": "confirmed",
            },
        },
    )
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request) or httpx.Response(200, json={"vulns": [advisory()]})
            )
        )
    ) as client:
        first = osv.refresh(configured_engine, client=client, now=1800000000)
        assert first["assets_checked"] == 1 and first["cve_findings"] == 1
        assert json.loads(requests[0].content) == {
            "package": {"name": "next", "ecosystem": "npm"},
            "version": "15.1.0",
        }
        assert "App dependency" not in requests[0].content.decode()
        assert correlate(configured_engine, enqueue=True)["queued"] == 1
        assert osv.refresh(configured_engine, client=client, now=1800000600)["assets_checked"] == 1
        assert correlate(configured_engine, enqueue=True)["queued"] == 0
    record = next(vulnerabilities(configured_engine, "CVE-2026-1234"))
    assert record["cvss"] is None and record["severity"] is None and record["sources"] == ["OSV"]
    evidence = match(Asset.model_validate({k: v for k, v in asset.items() if k != "id"}), record)
    assert evidence["confidence"] == "confirmed" and evidence["method"] == "osv_package_version"
    assert "declared package" in evidence["explanation"]
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    messages = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                messages.append(json.loads(request.content)["text"])
                or httpx.Response(200, json={"ok": True})
            )
        )
    ) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "sent"
    assert (
        "CVE-2026-1234" in messages[0]
        and "https://osv.dev/vulnerability/GHSA-example-1234" in messages[0]
    )
    assert "Sources: OSV" in messages[0] and "verify the installed inventory" in messages[0]


def test_failed_or_incomplete_sync_preserves_previous_snapshot(configured_engine):
    asset = package(configured_engine)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [advisory()]}))
    ) as client:
        assert osv.refresh(configured_engine, client=client, now=1800000000)["assets_checked"] == 1
    for response in [
        httpx.Response(503),
        httpx.Response(200, json={"vulns": [], "next_page_token": "repeat"}),
    ]:
        with httpx.Client(
            transport=httpx.MockTransport(lambda _, response=response: response)
        ) as client:
            result = osv.refresh(configured_engine, client=client, now=1800000100)
        assert result["assets_failed"] == 1
        with configured_engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM osv_findings WHERE asset_id=:id"),
                    {"id": asset["id"]},
                ).scalar_one()
                == 1
            )
            state = connection.execute(
                text("SELECT last_error FROM source_state WHERE source='osv'")
            ).scalar_one()
        assert "previous findings retained" in state


def test_rate_limit_stops_batch_and_honors_provider_retry_deadline(configured_engine):
    package(configured_engine)
    package(configured_engine, name="Other package", package="react", version="19.0.0")
    calls = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                calls.append(request) or httpx.Response(429, headers={"Retry-After": "7200"})
            )
        )
    ) as client:
        result = osv.refresh(configured_engine, client=client, now=1800000000)
    assert len(calls) == 1 and result["assets_failed"] == 1
    assert result["remaining_assets"] == 1 and result["retry_after"] == 7200
    with TestClient(app, base_url="http://localhost") as client:
        statuses = client.get("/api/sources/osv/status").json()
        assert len(statuses) == 1 and "HTTP 429" in statuses[0]["last_error"]


def test_monitor_persists_osv_retry_deadline(configured_engine, monkeypatch):
    from vulnrelay import monitor
    from vulnrelay.config import Settings

    monkeypatch.setattr(monitor, "sync_nvd", lambda *a, **k: 0)
    monkeypatch.setattr(monitor, "sync_kev", lambda *a, **k: 0)
    monkeypatch.setattr(monitor, "refresh_epss", lambda *a, **k: 0)
    monkeypatch.setattr(
        monitor,
        "refresh_osv",
        lambda *a, **k: {"assets_checked": 0, "assets_failed": 1, "retry_after": 7200},
    )
    result = monitor.cycle(
        configured_engine, Settings(osv_enabled=True), now=1800000000, process_deliveries=False
    )
    assert result["sources"]["osv"]["ok"] is False
    assert monitor.state(configured_engine)["next_osv"] == 1800007200


def test_monitor_does_not_query_osv_without_opt_in(configured_engine, monkeypatch):
    from vulnrelay import monitor
    from vulnrelay.config import Settings

    monkeypatch.setattr(monitor, "sync_nvd", lambda *a, **k: 0)
    monkeypatch.setattr(monitor, "sync_kev", lambda *a, **k: 0)
    monkeypatch.setattr(monitor, "refresh_epss", lambda *a, **k: 0)
    monkeypatch.setattr(monitor, "refresh_osv", lambda *a, **k: pytest.fail("OSV not enabled"))
    result = monitor.cycle(
        configured_engine, Settings(osv_enabled=False), now=1800000000, process_deliveries=False
    )
    assert "osv" not in result["sources"]


def test_pagination_and_withdrawn_or_non_cve_records(configured_engine):
    package(configured_engine)
    responses = [
        httpx.Response(200, json={"vulns": [advisory()], "next_page_token": "page-two"}),
        httpx.Response(
            200,
            json={
                "vulns": [
                    advisory("GHSA-example-5678", ["CVE-2026-5678"]),
                    advisory("GHSA-withdrawn", ["CVE-2026-9999"], withdrawn="2026-11-22T00:00:00Z"),
                    advisory("GHSA-only", []),
                ]
            },
        ),
    ]
    bodies = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: bodies.append(json.loads(request.content)) or responses.pop(0)
        )
    ) as client:
        result = osv.refresh(configured_engine, client=client)
    assert result["assets_checked"] == 1 and result["cve_findings"] == 2
    assert bodies[1]["page_token"] == "page-two"
    with configured_engine.connect() as connection:
        assert set(connection.execute(text("SELECT cve_id FROM osv_findings")).scalars()) == {
            "CVE-2026-1234",
            "CVE-2026-5678",
        }


def test_duplicate_and_conflicting_osv_pages_do_not_corrupt_snapshot(configured_engine):
    package(configured_engine)
    first = advisory()
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [first, first]}))
    ) as client:
        assert osv.refresh(configured_engine, client=client)["cve_findings"] == 1
    conflicting = {**first, "modified": "2026-11-21T00:00:00Z", "withdrawn": "2026-11-21T00:00:00Z"}
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"vulns": [first, conflicting]})
        )
    ) as client:
        assert osv.refresh(configured_engine, client=client)["assets_failed"] == 1
    assert next(vulnerabilities(configured_engine, "CVE-2026-1234"), None) is not None


def test_changed_version_never_reuses_old_version_evidence(configured_engine):
    asset = package(configured_engine)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [advisory()]}))
    ) as client:
        osv.refresh(configured_engine, client=client)
    identity = asset.pop("id")
    updated = save_document(configured_engine, "assets", {**asset, "version": "16.0.0"}, identity)
    record = next(vulnerabilities(configured_engine, "CVE-2026-1234"), None)
    assert (
        record is None
        or match(Asset.model_validate({k: v for k, v in updated.items() if k != "id"}), record)
        is None
    )
    assert osv.asset_status(configured_engine) == []
    assert delete_document(configured_engine, "assets", identity)
    assert next(vulnerabilities(configured_engine, "CVE-2026-1234"), None) is None


def test_asset_change_during_query_does_not_save_obsolete_evidence(configured_engine):
    asset = package(configured_engine)
    identifier = asset.pop("id")

    def handler(_):
        save_document(configured_engine, "assets", {**asset, "version": "16.0.0"}, identifier)
        return httpx.Response(200, json={"vulns": [advisory()]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert osv.refresh(configured_engine, client=client)["assets_failed"] == 1
    assert next(vulnerabilities(configured_engine, "CVE-2026-1234"), None) is None


def test_package_cannot_match_unrelated_nvd_cve():
    asset = Asset(name="Package", kind="package", ecosystem="npm", package="next", version="1.0.0")
    unrelated = {
        "status": "Analyzed",
        "nvd": {
            "configurations": [
                {
                    "cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:any:other:1.0:*:*:*:*:*:*:*"}
                    ]
                }
            ]
        },
        "kev_record": {"product": "other"},
    }
    assert match(asset, unrelated) is None


@pytest.mark.parametrize("version", ["", "15.x", "^1.2.3", ">=1.0", "*"])
def test_package_requires_an_exact_version(version):
    with pytest.raises(ValidationError):
        Asset(name="package", kind="package", ecosystem="npm", package="next", version=version)


def test_pypi_identity_normalization_and_mismatched_record_rejection(configured_engine):
    package(configured_engine, ecosystem="PyPI", package="my_package", version="1.0")
    valid = advisory(ecosystem="PyPI", name="My-Package")
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [valid]}))
    ) as client:
        assert osv.refresh(configured_engine, client=client)["assets_checked"] == 1
    invalid = advisory(ecosystem="PyPI", name="other")
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [invalid]}))
    ) as client:
        assert osv.refresh(configured_engine, client=client)["assets_failed"] == 1
    assert next(vulnerabilities(configured_engine, "CVE-2026-1234"), None) is not None


def test_nvd_assessment_remains_primary_and_package_rule_fields_work(configured_engine):
    asset = package(configured_engine)
    connector = save_document(
        configured_engine, "connectors", {"name": "Channel", "chat_id": "-123"}
    )
    save_document(
        configured_engine,
        "rules",
        {
            "name": "npm policy",
            "assets": [asset["id"]],
            "destinations": [connector["id"]],
            "condition": {
                "kind": "all",
                "children": [
                    {"kind": "condition", "field": "ecosystem", "op": "eq", "value": "npm"},
                    {"kind": "condition", "field": "package", "op": "eq", "value": "next"},
                ],
            },
        },
    )
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities (id,modified,status,description,cvss_score,severity,nvd_raw)
        VALUES ('CVE-2026-1234','2026-11-22','Analyzed','NVD original',9.8,'CRITICAL','{}')""")
        )
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"vulns": [advisory()]}))
    ) as client:
        assert osv.refresh(configured_engine, client=client)["assets_checked"] == 1
    record = next(vulnerabilities(configured_engine, "CVE-2026-1234"))
    assert (
        record["description"] == "NVD original"
        and record["cvss"] == 9.8
        and record["cvss_source"] == "NVD"
    )
    assert record["sources"] == ["NVD", "OSV"]
    result = correlate(configured_engine, enqueue=True)
    assert result["queued"] == 1 and result["reports"][0]["matched"] is True


def test_opt_in_monitor_and_manual_cli_do_not_require_credentials(configured_engine, monkeypatch):
    monkeypatch.setattr(
        cli, "refresh_osv", lambda engine: {"assets_checked": 0, "assets_failed": 0}
    )
    result = CliRunner().invoke(cli.app, ["sync-osv"])
    assert result.exit_code == 0 and json.loads(result.stdout)["assets_checked"] == 0


def test_upgrade_preserves_existing_inventory_and_queue(configured_engine):
    asset = package(configured_engine)
    command.downgrade(Config("backend/alembic.ini"), "0009")
    command.upgrade(Config("backend/alembic.ini"), "head")
    with configured_engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM assets WHERE id=:id"), {"id": asset["id"]}
            ).scalar_one()
            == 1
        )
    assert (
        osv.refresh(
            configured_engine,
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}))
            ),
            now=time.time(),
        )["assets_checked"]
        == 1
    )
