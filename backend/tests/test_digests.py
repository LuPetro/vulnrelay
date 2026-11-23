import json
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_notification_core import seed
from typer.testing import CliRunner
from vulnrelay.api import app
from vulnrelay.cli import app as cli_app
from vulnrelay.db import create_database_engine
from vulnrelay.delivery import deliver_one, history, render
from vulnrelay.digests import (
    Digest,
    delete_digest,
    list_digests,
    next_run,
    refresh_digest,
    save_digest,
    schedule_due,
)

SLOT = datetime(2026, 11, 23, 8, 0, tzinfo=UTC).timestamp()


def create(engine, connector_id, scope="global", **overrides):
    return save_digest(
        engine,
        {
            "name": "Weekly security",
            "scope": scope,
            "frequency": "weekly",
            "timezone": "UTC",
            "time": "08:00",
            "weekday": 0,
            "destinations": [connector_id],
            **overrides,
        },
        now=SLOT - 3600,
    )


def intelligence(engine):
    asset, connector, rule = seed(engine)
    with engine.begin() as connection:
        connection.execute(text("UPDATE vulnerabilities SET published='2026-11-22T10:00:00.000'"))
        connection.execute(
            text("""INSERT INTO vulnerabilities (id,modified,published,description,status,cvss_score,severity,nvd_raw)
            VALUES ('CVE-2026-9999','2026-11-22','2026-11-22T12:00:00.000','Different product','Analyzed',7.5,'HIGH',:raw)"""),
            {"raw": json.dumps({"configurations": []})},
        )
        connection.execute(
            text(
                "INSERT INTO source_state (source,last_success_at) VALUES ('nvd','2026-11-23 07:00:00')"
            )
        )
    return asset, connector, rule


def test_weekly_global_digest_persists_and_sends_once_after_restart(configured_engine, monkeypatch):
    _, connector, _ = intelligence(configured_engine)
    report = create(configured_engine, connector["id"])
    assert report["next_run"] == SLOT
    assert schedule_due(configured_engine, now=SLOT - 1) == 0
    assert schedule_due(configured_engine, now=SLOT + 1) == 1
    restarted = create_database_engine(str(configured_engine.url))
    try:
        assert schedule_due(restarted, now=SLOT + 1) == 0
        assert list_digests(restarted)[0]["next_run"] > SLOT
    finally:
        restarted.dispose()
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
        assert deliver_one(configured_engine, now=SLOT + 2, client=client)["state"] == "sent"
        assert deliver_one(configured_engine, now=SLOT + 20, client=client) is None
    assert "Worldwide CVEs" in messages[0]
    assert "CVE-2026-1234" in messages[0] and "CVE-2026-9999" in messages[0]
    assert "NVD last successful sync" in messages[0] and "coverage can be incomplete" in messages[0]
    assert "AI-generated" not in messages[0]


def test_relevant_digest_uses_enabled_rules_and_excludes_unmatched_products(configured_engine):
    _, connector, rule = intelligence(configured_engine)
    report = create(configured_engine, connector["id"], "relevant")
    payload = {
        "digest": True,
        "digest_id": report["id"],
        "period_start": SLOT - 7 * 86400,
        "period_end": SLOT,
    }
    data, error = refresh_digest(configured_engine, payload, connector["id"])
    assert error is None
    assert [row["id"] for row in data["entries"]] == ["CVE-2026-1234"]
    assert data["entries"][0]["match"]["asset"] == "Production web"
    assert data["entries"][0]["match"]["confidence"] == "potential"
    assert "Why: Production web" in render(data)
    assert data["scanned"] == 2 and data["candidates"] == 2
    from vulnrelay.store import save_document

    identifier = rule.pop("id")
    save_document(configured_engine, "rules", {**rule, "enabled": False}, identifier)
    data, _ = refresh_digest(configured_engine, payload, connector["id"])
    assert data["entries"] == []


def test_report_is_cancelled_after_deletion_or_destination_removal(configured_engine, monkeypatch):
    _, connector, _ = intelligence(configured_engine)
    report = create(configured_engine, connector["id"])
    assert schedule_due(configured_engine, now=SLOT + 1) == 1
    assert delete_digest(configured_engine, report["id"])
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: pytest.fail("must not deliver"))
    ) as client:
        result = deliver_one(configured_engine, now=SLOT + 2, client=client)
    assert result["state"] == "cancelled" and "removed" in result["error"]
    assert history(configured_engine)[0]["state"] == "cancelled"


def test_missed_periods_do_not_flood_queue(configured_engine):
    _, connector, _ = intelligence(configured_engine)
    report = create(configured_engine, connector["id"])
    assert schedule_due(configured_engine, now=SLOT + 21 * 86400 + 1) == 1
    with configured_engine.connect() as connection:
        payload = json.loads(connection.execute(text("SELECT payload FROM outbox")).scalar_one())
    assert payload["period_end"] == SLOT + 21 * 86400
    assert schedule_due(configured_engine, now=SLOT + 21 * 86400 + 2) == 0
    assert list_digests(configured_engine)[0]["id"] == report["id"]


def test_timezones_handle_spring_gap_and_autumn_fold():
    cfg = Digest(
        name="DST", frequency="daily", time="02:30", timezone="Europe/Vienna", destinations=["x"]
    )
    spring = datetime(2026, 3, 28, 12, tzinfo=UTC).timestamp()
    local = datetime.fromtimestamp(next_run(cfg, spring), ZoneInfo("Europe/Vienna"))
    assert (local.year, local.month, local.day, local.hour, local.minute) == (2026, 3, 29, 3, 0)
    autumn = datetime(2026, 10, 24, 12, tzinfo=UTC).timestamp()
    repeated = datetime.fromtimestamp(next_run(cfg, autumn), ZoneInfo("Europe/Vienna"))
    assert (repeated.month, repeated.day, repeated.hour, repeated.minute, repeated.fold) == (
        10,
        25,
        2,
        30,
        0,
    )
    assert next_run(cfg, repeated.timestamp()) > repeated.timestamp() + 20 * 3600


def test_message_length_and_missing_sources_are_honest():
    payload = {
        "digest": True,
        "name": "Weekly",
        "scope": "global",
        "period_start": SLOT - 86400,
        "period_end": SLOT,
        "entries": [
            {"id": "CVE-2026-1234", "severity": "HIGH", "cvss": None, "epss": None, "kev": None}
        ]
        * 20,
        "scanned": 20,
        "candidates": 3000,
        "nvd_synced": None,
    }
    message = render(payload, max_bytes=3600)
    assert len(message.encode("utf-16-le")) <= 3600
    assert "NVD last successful sync: unknown" in message
    assert "Screened 20 of 3000" in message
    assert "unknown" in message and "coverage can be incomplete" in message


def test_api_creation_preview_and_security(configured_engine):
    _, connector, _ = intelligence(configured_engine)
    headers = {"x-vulnrelay-request": "1"}
    with TestClient(app, base_url="http://localhost") as client:
        document = {"name": "Daily", "frequency": "daily", "destinations": [connector["id"]]}
        assert client.post("/api/digests", json=document).status_code == 403
        assert (
            client.post(
                "/api/digests", headers=headers, json={**document, "destinations": ["missing"]}
            ).status_code
            == 422
        )
        response = client.post("/api/digests", headers=headers, json=document)
        assert response.status_code == 201
        identifier = response.json()["id"]
        assert client.get("/api/digests").json()[0]["frequency"] == "daily"
        preview = client.post(f"/api/digests/{identifier}/preview", headers=headers)
        assert preview.status_code == 200 and preview.json()["scope"] == "global"
        assert client.delete(f"/api/digests/{identifier}", headers=headers).status_code == 200
        assert client.get("/api/digests").json() == []


def test_cli_can_configure_preview_and_delete_reports(configured_engine, tmp_path):
    _, connector, _ = intelligence(configured_engine)
    config = {"name": "CLI report", "frequency": "weekly", "destinations": [connector["id"]]}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(config))
    runner = CliRunner()
    created = runner.invoke(cli_app, ["reports", "add", str(path)])
    assert created.exit_code == 0
    identifier = json.loads(created.stdout)["id"]
    listed = runner.invoke(cli_app, ["reports", "list"])
    assert json.loads(listed.stdout)[0]["id"] == identifier
    preview = runner.invoke(cli_app, ["reports", "preview", identifier])
    assert preview.exit_code == 0 and json.loads(preview.stdout)["scope"] == "global"
    deleted = runner.invoke(cli_app, ["reports", "delete", identifier])
    assert deleted.exit_code == 0 and json.loads(deleted.stdout)["deleted"]


def test_publication_window_handles_optional_fractional_seconds(configured_engine):
    _, connector, _ = intelligence(configured_engine)
    report = create(configured_engine, connector["id"])
    with configured_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE vulnerabilities SET published='2026-11-16T08:00:00Z' WHERE id='CVE-2026-1234'"
            )
        )
        connection.execute(
            text(
                "UPDATE vulnerabilities SET published='2026-11-23T08:00:00.000' WHERE id='CVE-2026-9999'"
            )
        )
    data, error = refresh_digest(
        configured_engine,
        {
            "digest": True,
            "digest_id": report["id"],
            "period_start": SLOT - 7 * 86400,
            "period_end": SLOT,
        },
        connector["id"],
    )
    assert error is None and [item["id"] for item in data["entries"]] == ["CVE-2026-1234"]


def test_migration_preserves_prior_ai_settings_and_queued_alerts(configured_engine):
    from vulnrelay import ai
    from vulnrelay.pipeline import correlate

    _, connector, _ = intelligence(configured_engine)
    ai.save_settings(configured_engine, ai.AISettings(enabled=True, model="model"))
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    command.downgrade(Config("backend/alembic.ini"), "0008")
    command.upgrade(Config("backend/alembic.ini"), "head")
    assert ai.settings(configured_engine).enabled
    assert history(configured_engine)[0]["connector_id"] == connector["id"]
    assert list_digests(configured_engine) == []
