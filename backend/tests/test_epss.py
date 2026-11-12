import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.epss import lookup


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", f"sqlite:///{tmp_path / 'epss.db'}")
    get_settings.cache_clear()
    command.upgrade(Config("backend/alembic.ini"), "head")
    engine = create_database_engine(get_settings().database_url)
    yield engine
    engine.dispose()
    get_settings.cache_clear()


def client(rows):
    return httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"status": "OK", "data": rows})))


def row(score="0.35", measured="2026-11-10"):
    return {"cve": "CVE-2026-1234", "epss": score, "percentile": "0.95", "date": measured}


def test_epss_lookup_and_no_score(database):
    with client([row()]) as http:
        assert lookup(database, "cve-2026-1234", client=http)["score"] == 0.35
    with client([]) as http:
        assert lookup(database, "CVE-2026-9999", client=http) is None
    with database.connect() as connection:
        assert connection.execute(text("SELECT percentile FROM epss_scores")).scalar_one() == 0.95


def test_bad_or_older_data_does_not_overwrite(database):
    with client([row()]) as http:
        lookup(database, "CVE-2026-1234", client=http)
    with client([row("1.1")]) as http, pytest.raises(ValueError):
        lookup(database, "CVE-2026-1234", client=http)
    with client([row("0.1", "2026-11-01")]) as http:
        assert lookup(database, "CVE-2026-1234", client=http)["score"] == 0.35
    with database.connect() as connection:
        assert connection.execute(text("SELECT score FROM epss_scores")).scalar_one() == 0.35
