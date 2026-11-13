import json
import time

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from typer.testing import CliRunner
from vulnrelay import cli, monitor, opencve, routes
from vulnrelay.api import app
from vulnrelay.config import Settings
from vulnrelay.delivery import deliver_one, enqueue_test, history, render
from vulnrelay.matching import match
from vulnrelay.pipeline import correlate, vulnerabilities
from vulnrelay.schemas import Asset
from vulnrelay.store import save_document

CVE = "CVE-2026-1234"
CPE = "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"


def record(cve_id=CVE, score=9.8):
    return {
        "cve": cve_id,
        "opencve": {
            "description": {"data": "Synthetic Example Server issue", "provider": "mitre"},
            "created": {"data": "2026-11-01T10:00:00Z", "provider": "mitre"},
            "updated": {"data": "2026-11-13T10:00:00Z", "provider": "nvd"},
            "metrics": {
                "cvssV3_1": {"data": {"score": score, "vector": "synthetic"}, "provider": "nvd"}
            },
            "vendors": {"data": ["example", "example$PRODUCT$server"], "providers": ["nvd"]},
            "cpes": {"data": [CPE], "providers": ["nvd"]},
            "references": {"data": ["https://example.org/advisory"], "providers": ["mitre"]},
            "weaknesses": {"data": ["CWE-20"], "providers": ["mitre"]},
        },
        "nvd": {"metrics": {"cvssV3_1": {"score": 7.5}}},
    }


def test_lookup_conditional_requests_and_original_provenance(configured_engine):
    requests = []

    def handler(request):
        requests.append(request)
        assert str(request.url) == opencve.record_url(CVE, raw=True)
        if len(requests) == 1:
            return httpx.Response(200, json=record(), headers={"ETag": '"example"'})
        assert request.headers["if-none-match"] == '"example"'
        return httpx.Response(304)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        first = opencve.lookup(configured_engine, CVE.lower(), client=client)
        assert first["cvss"] == 9.8 and first["assessments"][0]["provider"] == "nvd"
        assert opencve.lookup(configured_engine, CVE, client=client) == first
    with configured_engine.connect() as connection:
        row = connection.execute(text("SELECT * FROM opencve_records")).mappings().one()
        assert json.loads(row["raw"])["nvd"]["metrics"]["cvssV3_1"]["score"] == 7.5
        assert row["etag"] == '"example"' and row["checked_at"] >= row["synced_at"]


def test_missing_record_keeps_the_last_valid_assessment(configured_engine):
    responses = [httpx.Response(200, json=record()), httpx.Response(404)]
    with httpx.Client(transport=httpx.MockTransport(lambda _: responses.pop(0))) as client:
        saved = opencve.lookup(configured_engine, CVE, client=client)
        assert opencve.lookup(configured_engine, CVE, client=client) is None
    assert next(vulnerabilities(configured_engine, CVE))["opencve"] == saved


def test_migration_from_notification_alpha_preserves_configuration_and_queue(configured_engine):
    config = Config("backend/alembic.ini")
    command.downgrade(config, "0005")
    asset = save_document(
        configured_engine,
        "assets",
        {"name": "Existing server", "kind": "product", "product": "example"},
    )
    connector = save_document(
        configured_engine, "connectors", {"name": "Existing Telegram", "chat_id": "-123"}
    )
    message_id = enqueue_test(configured_engine, connector["id"])
    command.upgrade(config, "head")
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT id FROM assets")).scalar_one() == asset["id"]
        assert connection.execute(text("SELECT COUNT(*) FROM opencve_records")).scalar_one() == 0
    assert history(configured_engine)[0]["id"] == message_id
    assert history(configured_engine)[0]["state"] == "pending"


@pytest.mark.parametrize(
    "failure",
    [
        "older",
        "wrong_id",
        "bad_score",
        "bad_timestamp",
        "bad_json",
        "too_large",
        "redirect",
        "auth",
        "uncached_304",
    ],
)
def test_failed_lookup_preserves_previous_data_and_reports_sanitized_error(
    configured_engine, monkeypatch, failure
):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=record()))
    ) as client:
        opencve.lookup(configured_engine, CVE, client=client)
    bad = record()
    status, headers, content = 200, {}, None
    if failure == "older":
        bad["opencve"]["updated"]["data"] = "2026-01-01T00:00:00Z"
    elif failure == "wrong_id":
        bad["cve"] = "CVE-2026-9999"
    elif failure == "bad_score":
        bad["opencve"]["metrics"]["cvssV3_1"]["data"]["score"] = True
    elif failure == "bad_timestamp":
        bad["opencve"]["updated"]["data"] = "2026-11-13"
    elif failure == "bad_json":
        content = b"not-json secret-upstream-detail"
    elif failure == "too_large":
        monkeypatch.setattr(opencve, "MAX_BYTES", 10)
    elif failure == "redirect":
        status, headers = 302, {"Location": "https://untrusted.invalid/"}
    elif failure == "auth":
        status = 401
    elif failure == "uncached_304":
        status = 304
        with configured_engine.begin() as connection:
            connection.execute(text("UPDATE opencve_records SET normalized=NULL,etag=NULL"))
    with configured_engine.connect() as connection:
        before = dict(connection.execute(text("SELECT * FROM opencve_records")).mappings().one())
    requests = []

    def handler(request):
        requests.append(request)
        return (
            httpx.Response(status, headers=headers, content=content)
            if content is not None
            else httpx.Response(status, headers=headers, json=bad)
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client,
        pytest.raises((ValueError, httpx.HTTPError)),
    ):
        opencve.lookup(configured_engine, CVE, client=client, sleeper=lambda _: None)
    assert len(requests) == 1
    with configured_engine.connect() as connection:
        after = dict(connection.execute(text("SELECT * FROM opencve_records")).mappings().one())
        error = connection.execute(
            text("SELECT last_error FROM source_state WHERE source='opencve'")
        ).scalar_one()
    assert before == after and error == "OpenCVE lookup failed"


def test_rate_limits_retry_and_transport_failure_stop_the_batch(configured_engine):
    attempts, delays = [], []

    def handler(request):
        attempts.append(request)
        return (
            httpx.Response(429, headers={"Retry-After": "2"})
            if len(attempts) < 3
            else httpx.Response(200, json=record())
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert (
            opencve.lookup(configured_engine, CVE, client=client, sleeper=delays.append)["id"]
            == CVE
        )
    assert len(attempts) == 3 and delays == [2, 2]
    with configured_engine.begin() as connection:
        for cve_id in ("CVE-2026-2222", "CVE-2026-3333"):
            connection.execute(
                text(
                    "INSERT INTO vulnerabilities (id,modified,nvd_raw) VALUES (:id,'2026-11-13','{}')"
                ),
                {"id": cve_id},
            )
    failures = []

    def failing(request):
        failures.append(request)
        raise httpx.ConnectError("private upstream exception", request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(failing)) as client,
        pytest.raises(httpx.ConnectError),
    ):
        opencve.refresh(configured_engine, client=client, sleeper=lambda _: None)
    assert len(failures) == 3


def test_long_upstream_cooldown_stops_requests_without_sleeping(configured_engine):
    requests, delays = [], []

    def handler(request):
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "7200"})

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        opencve.lookup(configured_engine, CVE, client=client, sleeper=delays.append)
    assert len(requests) == 1 and delays == []


def test_monitor_persists_long_opencve_retry_after(configured_engine, monkeypatch):
    for name in ("sync_nvd", "sync_kev", "refresh_epss"):
        monkeypatch.setattr(monitor, name, lambda *args, **kwargs: 0)
    response = httpx.Response(
        429,
        headers={"Retry-After": "7200"},
        request=httpx.Request("GET", opencve.record_url(CVE, raw=True)),
    )

    def deferred(*args, **kwargs):
        response.raise_for_status()

    monkeypatch.setattr(monitor, "refresh_opencve", deferred)
    settings = Settings(database_url=str(configured_engine.url), opencve_enabled=True)
    started = time.time()
    result = monitor.cycle(configured_engine, settings, now=started)
    assert result["sources"]["opencve"]["ok"] is False
    assert monitor.state(configured_engine)["next_opencve"] >= started + 7200
    assert (
        "opencve" not in monitor.cycle(configured_engine, settings, now=started + 1801)["sources"]
    )


def test_bounded_refresh_caches_misses_and_does_not_create_fake_cves(configured_engine):
    with configured_engine.begin() as connection:
        for cve_id in ("CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"):
            connection.execute(
                text(
                    "INSERT INTO vulnerabilities (id,modified,nvd_raw) VALUES (:id,'2026-11-13','{}')"
                ),
                {"id": cve_id},
            )
    checked = []

    def handler(request):
        checked.append(request.url.path)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert opencve.refresh(configured_engine, batch_size=2, client=client) == {
            "checked": 2,
            "found": 0,
        }
        assert opencve.refresh(configured_engine, batch_size=2, client=client) == {
            "checked": 1,
            "found": 0,
        }
        assert opencve.refresh(configured_engine, batch_size=2, client=client) == {
            "checked": 0,
            "found": 0,
        }
        assert opencve.lookup(configured_engine, "CVE-2026-9999", client=client) is None
    assert len(set(checked)) == 4
    assert len(list(vulnerabilities(configured_engine))) == 3
    with pytest.raises(ValueError):
        opencve.record_url("CVE-2026-1234/../../private")


def test_opencve_only_alerts_use_conservative_matching_and_normal_deduplication(
    configured_engine, monkeypatch
):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=record()))
    ) as client:
        opencve.lookup(configured_engine, CVE, client=client)
    asset = save_document(
        configured_engine,
        "assets",
        {"name": "Server", "kind": "vendor_product", "vendor": "example", "product": "server"},
    )
    connector = save_document(configured_engine, "connectors", {"name": "Test", "chat_id": "-123"})
    save_document(
        configured_engine,
        "rules",
        {
            "name": "High",
            "assets": [asset["id"]],
            "destinations": [connector["id"]],
            "condition": {"kind": "condition", "field": "cvss", "op": "gte", "value": 9},
        },
    )
    data = next(vulnerabilities(configured_engine, CVE))
    assert data["cvss"] == 9.8 and data["cvss_source"] == "OpenCVE"
    assert data["kev"] is None and data["epss"] is None
    cpe_asset = Asset(name="Versioned", kind="cpe", cpe=CPE)
    assert match(cpe_asset, data)["confidence"] == "unknown"
    assert match(Asset(name="Other", kind="product", product="unrelated"), data) is None
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    with configured_engine.connect() as connection:
        payload = json.loads(connection.execute(text("SELECT payload FROM outbox")).scalar_one())
    message = render(payload)
    assert "CVSS assessment: OpenCVE" in message and opencve.record_url(CVE) in message
    assert payload["match"]["confidence"] == "potential"
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)

    def send(request):
        assert "CVSS assessment: OpenCVE" in json.loads(request.content)["text"]
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(send)) as telegram:
        assert deliver_one(configured_engine, now=2000000000, client=telegram)["state"] == "sent"
    # An NVD assessment remains primary and the separate OpenCVE score is still inspectable.
    with configured_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO vulnerabilities (id,modified,cvss_score,severity,nvd_raw,status) VALUES (:id,'2026-11-13',0,'NONE','{}','Analyzed')"
            ),
            {"id": CVE},
        )
    data = next(vulnerabilities(configured_engine, CVE))
    assert data["cvss"] == 0 and data["cvss_source"] == "NVD"
    assert data["opencve"]["cvss"] == 9.8
    with configured_engine.begin() as connection:
        connection.execute(text("UPDATE vulnerabilities SET status='Rejected'"))
    assert correlate(configured_engine)["reports"] == []


def test_cli_and_api_lookup_and_offline_details(configured_engine, monkeypatch):
    original = opencve.lookup
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=record()))
    ) as client:

        def lookup(engine, cve_id):
            return original(engine, cve_id, client=client)

        monkeypatch.setattr(cli, "lookup_opencve", lookup)
        result = CliRunner().invoke(cli.app, ["lookup-opencve", CVE])
        assert result.exit_code == 0 and json.loads(result.stdout)["found"] is True
        result = CliRunner().invoke(cli.app, ["cve", CVE])
        assert result.exit_code == 0 and json.loads(result.stdout)["opencve"]["id"] == CVE
        monkeypatch.setattr(routes, "lookup_opencve", lookup)
        with TestClient(app, base_url="http://localhost") as api:
            path = f"/api/sources/opencve/{CVE}/lookup"
            assert api.post(path).status_code == 403
            assert api.post(path, headers={"x-vulnrelay-request": "1"}).json()["found"] is True
            assert (
                api.get(f"/api/vulnerabilities/{CVE}").json()["vulnerability"]["opencve"]["id"]
                == CVE
            )
            assert api.get("/api/overview").json()["opencve_enabled"] is False


def test_optional_monitoring_is_persistent_and_source_failures_are_isolated(
    configured_engine, monkeypatch
):
    for name in ("sync_nvd", "sync_kev", "refresh_epss"):
        monkeypatch.setattr(monitor, name, lambda *args, **kwargs: 0)
    calls = []

    def refresh(*args, **kwargs):
        calls.append(kwargs["batch_size"])
        raise ValueError("synthetic source error")

    monkeypatch.setattr(monitor, "refresh_opencve", refresh)
    disabled = Settings(database_url=str(configured_engine.url), opencve_enabled=False)
    assert "opencve" not in monitor.cycle(configured_engine, disabled, now=1)["sources"]
    enabled = disabled.model_copy(update={"opencve_enabled": True, "opencve_batch_size": 3})
    assert monitor.cycle(configured_engine, enabled, now=2)["sources"]["opencve"]["ok"] is False
    assert monitor.cycle(configured_engine, enabled, now=3)["sources"] == {}
    assert calls == [3]
