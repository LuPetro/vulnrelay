"""NVD request pacing and persisted recovery without live requests or real waits."""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from vulnrelay import monitor, nvd
from vulnrelay.api import app
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine


@pytest.mark.parametrize("status", [429, 503])
def test_request_retries_are_spread_and_jittered(monkeypatch, status):
    monkeypatch.setattr(nvd.random, "uniform", lambda low, high: high)
    responses = [httpx.Response(status) for _ in range(3)] + [httpx.Response(200, json={})]
    waits = []
    with httpx.Client(transport=httpx.MockTransport(lambda _: responses.pop(0))) as client:
        assert nvd._get(client, {}, {}, waits.append) == {}
    assert waits == [7.5, 15, 30]


@pytest.mark.parametrize("header", ["120", "120000"])
def test_long_server_cooldown_is_deferred_without_sleeping(header):
    calls = []
    waits = []

    def request(_):
        calls.append(1)
        return httpx.Response(503, headers={"Retry-After": header})

    with (
        httpx.Client(transport=httpx.MockTransport(request)) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        nvd._get(client, {}, {}, waits.append)
    assert calls == [1]
    assert waits == []


def test_retry_after_dates_and_invalid_values():
    deadline = datetime.now(UTC) + timedelta(minutes=10)
    response = httpx.Response(503, headers={"Retry-After": format_datetime(deadline)})
    assert 590 < nvd.retry_after_seconds(response) <= 600
    for header in ["NaN", "inf", "-10", "bad", ""]:
        assert nvd.retry_after_seconds(httpx.Response(503, headers={"Retry-After": header})) == 0


@pytest.fixture
def monitor_sources(configured_engine, monkeypatch):
    monkeypatch.setattr(monitor, "sync_kev", lambda _: 0)
    monkeypatch.setattr(monitor, "refresh_epss", lambda _: 0)
    monkeypatch.setattr(monitor, "deliver_one", lambda _: None)
    monkeypatch.setattr(monitor.random, "uniform", lambda low, high: high)
    return configured_engine


def test_monitor_backoff_restart_and_success_reset(monitor_sources, monkeypatch):
    engine = monitor_sources
    request = httpx.Request("GET", nvd.URL)
    response = httpx.Response(503, request=request)

    def fail(*args, **kwargs):
        raise httpx.HTTPStatusError("private upstream content", request=request, response=response)

    monkeypatch.setattr(monitor, "sync_nvd", fail)
    started = 2000000000
    for index, delay in enumerate([150, 300, 600, 1200, 1800, 1800], start=1):
        result = monitor.cycle(engine, get_settings(), now=started)
        assert result["sources"]["nvd"]["ok"] is False
        saved = monitor.state(engine)
        assert saved["failures_nvd"] == index
        assert saved["last_attempt_nvd"] == started
        assert saved["next_nvd"] == started + delay
        assert monitor.cycle(engine, get_settings(), now=started + 1)["sources"] == {}
        # New engine object has no process-local recovery state.
        replacement = create_database_engine(str(engine.url))
        assert monitor.state(replacement)["next_nvd"] == started + delay
        replacement.dispose()
        started += delay
    monkeypatch.setattr(monitor, "sync_nvd", lambda *args, **kwargs: 0)
    assert monitor.cycle(engine, get_settings(), now=started)["sources"]["nvd"]["ok"]
    assert monitor.state(engine)["failures_nvd"] == 0
    assert monitor.state(engine)["next_nvd"] == started + 1800


@pytest.mark.parametrize("status,delay", [(503, 120000), (429, 120000), (403, 1800)])
def test_monitor_honors_provider_deadline_and_does_not_fast_retry_denial(
    monitor_sources, monkeypatch, status, delay
):
    request = httpx.Request("GET", nvd.URL)
    response = httpx.Response(status, request=request, headers={"Retry-After": "120000"})

    def fail(*args, **kwargs):
        raise httpx.HTTPStatusError("untrusted", request=request, response=response)

    monkeypatch.setattr(monitor, "sync_nvd", fail)
    monitor.cycle(monitor_sources, get_settings(), now=100)
    saved = monitor.state(monitor_sources)
    assert saved["next_nvd"] == 100 + delay
    assert saved["failures_nvd"] == (0 if status == 403 else 1)


def test_schedule_is_measured_from_request_completion(monitor_sources, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(monitor.time, "time", lambda: clock[0])

    def fail(*args, **kwargs):
        clock[0] = 200.0
        raise httpx.ReadTimeout("offline")

    monkeypatch.setattr(monitor, "sync_nvd", fail)
    monitor.cycle(monitor_sources, get_settings())
    assert monitor.state(monitor_sources)["next_nvd"] == 350


def test_overview_separates_last_failure_success_and_next_retry(configured_engine):
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO source_state (source,last_success_at,last_error)
            VALUES ('nvd','2026-11-15T10:00:00Z','NVD HTTP 503: upstream service unavailable; retry later.')""")
        )
    monitor.set_states(
        configured_engine,
        {"failures_nvd": 2, "next_nvd": 2000000500, "last_attempt_nvd": 2000000200},
    )
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/api/overview")
        assert response.status_code == 200
        source = response.json()["sources"][0]
        assert source["last_error"].startswith("NVD HTTP 503")
        assert source["last_success_at"] == "2026-11-15T10:00:00Z"
        assert source["retry_scheduled"] is True
        assert source["next_attempt_at"] == 2000000500
        assert source["last_attempt_at"] == 2000000200


def test_manual_success_resets_failure_streak(configured_engine):
    monitor.set_state(configured_engine, "failures_nvd", 5)
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, json={"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
            )
        )
    ) as client:
        assert nvd.sync(configured_engine, client=client) == 0
    assert monitor.state(configured_engine)["failures_nvd"] == 0
