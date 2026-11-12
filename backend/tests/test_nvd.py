from datetime import UTC, datetime

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.nvd import normalize, sync

NOW = datetime(2026, 11, 12, tzinfo=UTC)


def record(cve_id="CVE-2026-1234", modified="2026-11-11T01:00:00.000"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-11-10T00:00:00.000",
            "lastModified": modified,
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Example"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
        }
    }


@pytest.fixture
def engine(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", url)
    get_settings.cache_clear()
    command.upgrade(Config("backend/alembic.ini"), "head")
    db = create_database_engine(url)
    yield db
    db.dispose()
    get_settings.cache_clear()


def test_missing_metrics_and_rejected_record():
    result = normalize(
        {
            "cve": {
                "id": "CVE-2026-1111",
                "lastModified": "2026-11-11T00:00:00Z",
                "vulnStatus": "Rejected",
            }
        }
    )
    assert result["status"] == "Rejected"
    assert result["cvss_score"] is None


def test_pagination_retry_and_deduplication(engine):
    calls = []
    waits = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        index = int(request.url.params["startIndex"])
        return httpx.Response(
            200,
            json={
                "startIndex": index,
                "totalResults": 2,
                "vulnerabilities": [record(f"CVE-2026-123{index}")],
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert sync(engine, client=client, now=NOW, sleeper=waits.append) == 2
        assert waits == [3.0, 6.0]
        assert sync(engine, client=client, now=NOW.replace(hour=1), sleeper=waits.append) == 2
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT id, cvss_score, severity, nvd_raw FROM vulnerabilities")
        ).all()
        checkpoint = connection.execute(
            text("SELECT checkpoint FROM source_state WHERE source='nvd'")
        ).scalar_one()
    assert len(rows) == 2
    assert rows[0].cvss_score == 9.8 and rows[0].severity == "CRITICAL"
    assert '"cvssMetricV31"' in rows[0].nvd_raw
    assert checkpoint.startswith("2026-11-12T01:00:00")
    assert calls[3].url.params["lastModStartDate"].startswith("2026-11-11T23:55:00")


def test_failed_page_rolls_back_records_and_checkpoint(engine):
    def handler(request):
        index = int(request.url.params["startIndex"])
        if index:
            return httpx.Response(503)
        return httpx.Response(
            200, json={"startIndex": 0, "totalResults": 2, "vulnerabilities": [record()]}
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        sync(engine, client=client, now=NOW, sleeper=lambda _: None)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM vulnerabilities")).scalar_one() == 0
        state = connection.execute(
            text("SELECT checkpoint, last_error FROM source_state WHERE source='nvd'")
        ).one()
        assert state.checkpoint is None
        assert state.last_error == "NVD synchronization failed"


def test_older_record_cannot_overwrite_newer(engine):
    records = [
        record(modified="2026-11-12T00:00:00.000"),
        record(modified="2026-11-10T00:00:00.000"),
    ]
    records[1]["cve"]["descriptions"][0]["value"] = "stale"

    def handler(request):
        return httpx.Response(
            200, json={"startIndex": 0, "totalResults": 1, "vulnerabilities": [records.pop(0)]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        sync(engine, client=client, now=NOW, sleeper=lambda _: None)
        sync(engine, client=client, now=NOW.replace(hour=1), sleeper=lambda _: None)
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT description FROM vulnerabilities")).scalar_one()
            == "Example"
        )
