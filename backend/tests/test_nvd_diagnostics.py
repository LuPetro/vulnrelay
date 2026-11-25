"""Operator-visible diagnostics must be useful without exposing provider secrets."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from typer.testing import CliRunner
from vulnrelay import cli
from vulnrelay.api import app
from vulnrelay.config import get_settings
from vulnrelay.nvd import URL, failure_message, sync


def test_failed_sync_reason_reaches_overview(configured_engine):
    def deny(request):
        return httpx.Response(403, text="private upstream body")

    with (
        httpx.Client(transport=httpx.MockTransport(deny)) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        sync(configured_engine, client=client)
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/api/overview")
    assert response.status_code == 200
    source = next(s for s in response.json()["sources"] if s["source"] == "nvd")
    assert source["last_error"].startswith("NVD HTTP 403: access denied")
    assert "private upstream" not in response.text


@pytest.mark.parametrize("status", [301, 400, 401, 403, 404, 429, 500, 503])
def test_http_diagnostics_never_reflect_provider_content(status):
    request = httpx.Request("GET", URL, headers={"apiKey": "secret-test-value"})
    error = httpx.HTTPStatusError(
        "secret exception text",
        request=request,
        response=httpx.Response(status, text="secret body", headers={"message": "secret header"}),
    )
    message = failure_message(error)
    assert message.startswith(f"NVD HTTP {status}:")
    assert "secret" not in message
    assert "https://" not in message


@pytest.mark.parametrize("key", ["", "secret-test-value"])
def test_probe_without_database_or_monitor_lock(monkeypatch, tmp_path, key):
    monkeypatch.setenv("VULNRELAY_NVD_API_KEY", key)
    database = tmp_path / "not-created.db"
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()

    def forbidden(*args, **kwargs):
        raise AssertionError("The probe must not open a database or take the monitor lock")

    def request(url, **kwargs):
        assert url == URL
        assert kwargs == {
            "params": {"resultsPerPage": 1},
            "headers": {"apiKey": key} if key else {},
            "timeout": 10,
            "follow_redirects": False,
        }
        return httpx.Response(200, request=httpx.Request("GET", url), json={"vulnerabilities": []})

    monkeypatch.setattr(cli, "create_database_engine", forbidden)
    monkeypatch.setattr(cli, "monitor_lock", forbidden)
    monkeypatch.setattr(cli.httpx, "get", request)
    try:
        result = CliRunner().invoke(cli.app, ["check-nvd", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] and payload["http_status"] == 200
        assert payload["api_key_configured"] is bool(key)
        assert "does not verify a full synchronization" in payload["message"]
        assert "secret-test-value" not in result.output
        assert not database.exists()
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize("failure", [403, 429, httpx.ReadTimeout, "bad_json", "bad_shape"])
@pytest.mark.parametrize("json_output", [False, True])
def test_probe_reports_failure_with_nonzero_exit(monkeypatch, failure, json_output):
    def request(url, **kwargs):
        request = httpx.Request("GET", url)
        if isinstance(failure, int):
            return httpx.Response(failure, request=request, text="private upstream body")
        if failure == "bad_json":
            return httpx.Response(200, request=request, text="private upstream body")
        if failure == "bad_shape":
            return httpx.Response(200, request=request, json=[])
        raise failure("private upstream exception", request=request)

    monkeypatch.setattr(cli.httpx, "get", request)
    result = CliRunner().invoke(cli.app, ["check-nvd", *(["--json"] if json_output else [])])
    assert result.exit_code == 1, result.output
    assert "private upstream" not in result.output
    if json_output:
        assert json.loads(result.output)["ok"] is False
    else:
        assert "Checking NVD connectivity" in result.output


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (httpx.ReadTimeout("private detail"), "NVD request timed out"),
        (SQLAlchemyError("private detail"), "NVD database operation failed"),
        (RuntimeError("private detail"), "another monitor or synchronization may be running"),
    ],
)
def test_manual_sync_reports_safe_diagnostic(configured_engine, monkeypatch, error, expected):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "sync_nvd", fail)
    result = CliRunner().invoke(cli.app, ["sync"])
    assert result.exit_code == 1
    assert expected in result.output
    assert "private detail" not in result.output
