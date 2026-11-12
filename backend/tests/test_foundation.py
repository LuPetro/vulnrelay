from fastapi.testclient import TestClient
from sqlalchemy import text
from typer.testing import CliRunner

from vulnrelay.api import app
from vulnrelay.cli import app as cli
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine


def test_health_and_wal(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", f"sqlite:///{tmp_path / 'data.db'}")
    get_settings.cache_clear()
    try:
        with TestClient(app, base_url="http://localhost") as client:
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok", "database": "reachable"}
        engine = create_database_engine(get_settings().database_url)
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
        engine.dispose()
    finally:
        get_settings.cache_clear()


def test_status_is_honest(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", f"sqlite:///{tmp_path / 'data.db'}")
    get_settings.cache_clear()
    try:
        result = CliRunner().invoke(cli, ["status", "--json"])
        assert result.exit_code == 0
        assert '"last_cycle": null' in result.stdout
    finally:
        get_settings.cache_clear()


def test_remote_start_is_rejected(monkeypatch):
    monkeypatch.setenv("VULNRELAY_HOST", "0.0.0.0")
    get_settings.cache_clear()
    try:
        result = CliRunner().invoke(cli, ["start"])
        assert result.exit_code == 1
        assert "authentication is not implemented" in result.output
    finally:
        get_settings.cache_clear()
