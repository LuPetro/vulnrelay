import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from typer.testing import CliRunner
from vulnrelay.cli import app
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.kev import sync


@pytest.fixture
def database(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'kev.db'}"
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", url)
    get_settings.cache_clear()
    command.upgrade(Config("backend/alembic.ini"), "head")
    engine = create_database_engine(url)
    yield engine
    engine.dispose()
    get_settings.cache_clear()


def catalog(cve_id="CVE-2026-1234", released="2026-11-11T00:00:00Z"):
    return {
        "dateReleased": released,
        "count": 1,
        "vulnerabilities": [
            {"cveID": cve_id, "dateAdded": "2026-11-10", "requiredAction": "Review vendor guidance"}
        ],
    }


def request(payload):
    return httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)))


def test_sync_and_cli_explain_membership(database):
    with request(catalog()) as client:
        assert sync(database, client=client) == 1
    output = CliRunner().invoke(app, ["cve", "CVE-2026-1234"])
    assert output.exit_code == 0
    assert '"kev_status": "listed"' in output.stdout
    assert '"requiredAction": "Review vendor guidance"' in output.stdout


def test_invalid_catalog_preserves_previous_snapshot(database):
    with request(catalog()) as client:
        sync(database, client=client)
    incomplete = catalog("CVE-2026-5678")
    incomplete["count"] = 2
    with request(incomplete) as client, pytest.raises(ValueError):
        sync(database, client=client)
    with database.connect() as connection:
        assert (
            connection.execute(text("SELECT cve_id FROM kev_entries")).scalar_one()
            == "CVE-2026-1234"
        )
        state = connection.execute(
            text("SELECT checkpoint, last_error FROM source_state WHERE source='cisa_kev'")
        ).one()
        assert state.checkpoint.startswith("2026-11-11")
        assert state.last_error == "CISA KEV synchronization failed"


def test_older_catalog_is_rejected_and_success_clears_error(database):
    with request(catalog()) as client:
        sync(database, client=client)
    with (
        request(catalog("CVE-2026-9999", "2026-11-01T00:00:00Z")) as client,
        pytest.raises(ValueError),
    ):
        sync(database, client=client)
    with request(catalog("CVE-2026-5678", "2026-11-12T00:00:00Z")) as client:
        sync(database, client=client)
    with database.connect() as connection:
        assert (
            connection.execute(text("SELECT cve_id FROM kev_entries")).scalar_one()
            == "CVE-2026-5678"
        )
        assert (
            connection.execute(
                text("SELECT last_error FROM source_state WHERE source='cisa_kev'")
            ).scalar_one()
            is None
        )


def test_unknown_status_without_a_catalog(database):
    with database.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities (id, modified, nvd_raw)
                         VALUES ('CVE-2026-1234', '2026-11-11', '{}')""")
        )
    result = CliRunner().invoke(app, ["cve", "CVE-2026-1234"])
    assert result.exit_code == 0
    assert '"kev_status": "unknown"' in result.stdout
