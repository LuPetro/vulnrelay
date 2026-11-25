import json
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from typer.testing import CliRunner
from vulnrelay.api import app
from vulnrelay.cli import app as cli
from vulnrelay.monitor import set_state
from vulnrelay.operations import backup_sqlite, worker_health
from vulnrelay.pipeline import correlate
from vulnrelay.store import save_document


def test_backup_captures_wal_and_refuses_overwrite(configured_engine, tmp_path):
    save_document(
        configured_engine,
        "assets",
        {"name": "Private server", "kind": "product", "product": "nginx"},
    )
    target = tmp_path / "snapshot.db"
    result = backup_sqlite(configured_engine, target)
    assert result["integrity"] == "ok"
    assert os.stat(target).st_mode & 0o777 == 0o600
    with sqlite3.connect(target) as connection:
        document = connection.execute("SELECT document FROM assets").fetchone()[0]
        assert json.loads(document)["name"] == "Private server"
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        backup_sqlite(configured_engine, target)
    assert target.read_bytes() == before
    with pytest.raises(ValueError):
        backup_sqlite(configured_engine, configured_engine.url.database)


def test_readiness_checks_schema_and_worker_health(configured_engine):
    assert worker_health(configured_engine, now=100) is False
    set_state(configured_engine, "delivery_heartbeat", 100)
    assert worker_health(configured_engine, now=110) is True
    assert worker_health(configured_engine, now=240) is False
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/ready").status_code == 200
        with configured_engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num='old'"))
        assert client.get("/ready").status_code == 503


def test_api_rejects_oversized_and_malformed_requests(configured_engine, monkeypatch):
    from vulnrelay.config import get_settings

    with TestClient(app, base_url="http://localhost") as client:
        headers = {"x-vulnrelay-request": "1"}
        response = client.post(
            "/api/config/assets", content=b"x" * (1024 * 1024 + 1), headers=headers
        )
        assert response.status_code == 413
        response = client.post(
            "/api/config/assets", json={}, headers={**headers, "origin": "http://[invalid"}
        )
        assert response.status_code == 403
    monkeypatch.setenv("VULNRELAY_API_TOKEN", "valid-token")
    get_settings.cache_clear()
    with TestClient(app, base_url="http://localhost") as client:
        assert (
            client.get(
                "/api/overview", headers={"authorization": "Bearer café".encode()}
            ).status_code
            == 401
        )


def test_no_assets_does_not_load_entire_feed(configured_engine, monkeypatch):
    from vulnrelay import pipeline

    def forbidden(*args, **kwargs):
        raise AssertionError("Feed was loaded without any configured assets/rules")

    monkeypatch.setattr(pipeline, "vulnerabilities", forbidden)
    assert correlate(configured_engine)["evaluations"] == 0


def test_init_and_backup_cli(configured_engine, tmp_path):
    result = CliRunner().invoke(cli, ["init"])
    assert result.exit_code == 0
    result = CliRunner().invoke(cli, ["backup", str(tmp_path / "cli-backup.db")])
    assert result.exit_code == 0 and '"integrity": "ok"' in result.stdout
    assert CliRunner().invoke(cli, ["engine-health"]).exit_code == 1


def test_chunked_request_cannot_bypass_body_limit():
    import asyncio

    from vulnrelay.http_limits import BodyLimitMiddleware

    async def scenario():
        chunks = [
            {"type": "http.request", "body": b"a" * 600, "more_body": True},
            {"type": "http.request", "body": b"b" * 600, "more_body": False},
        ]
        sent = []

        async def receive():
            return chunks.pop(0)

        async def send(message):
            sent.append(message)

        async def forbidden_app(*args):
            raise AssertionError("Oversized JSON reached the application")

        await BodyLimitMiddleware(forbidden_app, limit=1000)(
            {"type": "http", "method": "POST", "path": "/api/config/assets", "headers": []},
            receive,
            send,
        )
        assert sent[0]["status"] == 413

    asyncio.run(scenario())


def test_correlation_keyset_batches_do_not_skip_records(configured_engine):
    save_document(
        configured_engine, "assets", {"name": "Fixture", "kind": "keyword", "keyword": "fixture"}
    )
    connector = save_document(
        configured_engine, "connectors", {"name": "Test", "chat_id": "-123456"}
    )
    save_document(
        configured_engine,
        "rules",
        {
            "name": "Critical",
            "destinations": [connector["id"]],
            "condition": {"kind": "condition", "field": "cvss", "op": "gte", "value": 9},
        },
    )
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities (id,modified,status,description,cvss_score,nvd_raw)
            VALUES (:id,'2026-11-12','Analyzed','fixture',9.8,'{}')"""),
            [{"id": f"CVE-2026-{10000 + number}"} for number in range(1001)],
        )
    result = correlate(configured_engine, enqueue=True, limit=1)
    assert result["evaluations"] == result["queued"] == 1001
    assert result["truncated"] is True and len(result["reports"]) == 1
    assert correlate(configured_engine, enqueue=True, limit=0)["queued"] == 0
