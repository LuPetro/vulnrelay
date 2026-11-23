import hashlib
import hmac
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_notification_core import seed
from vulnrelay.api import app
from vulnrelay.config import get_settings
from vulnrelay.delivery import deliver_one, enqueue_test, history, send_generic_webhook
from vulnrelay.pipeline import correlate
from vulnrelay.schemas import Connector
from vulnrelay.store import save_document

FIXTURE_KEY = "-".join(("synthetic", "signing", "fixture"))


@pytest.fixture
def webhook_environment(monkeypatch):
    monkeypatch.setenv("VULNRELAY_WEBHOOK_URL", "https://receiver.example.org/alerts")
    monkeypatch.setenv("VULNRELAY_WEBHOOK_KEY", FIXTURE_KEY)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    get_settings.cache_clear()


def config():
    return Connector(name="Webhook", kind="webhook", webhook_env="VULNRELAY_WEBHOOK_URL")


def test_signed_event_is_pinned_structured_and_deduplicated(configured_engine, webhook_environment):
    _, _, rule = seed(configured_engine)
    destination = save_document(configured_engine, "connectors", config().model_dump())
    identifier = rule.pop("id")
    save_document(
        configured_engine, "rules", {**rule, "destinations": [destination["id"]]}, identifier
    )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "8.8.8.8" and request.headers["host"] == "receiver.example.org"
        assert request.extensions["sni_hostname"] == "receiver.example.org"
        expected = hmac.new(FIXTURE_KEY.encode(), request.content, hashlib.sha256).hexdigest()
        assert request.headers["x-vulnrelay-signature"] == "sha256=" + expected
        return httpx.Response(204)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = deliver_one(configured_engine, now=2000000000, client=client)
    assert result["state"] == "sent" and len(calls) == 1
    body = json.loads(calls[0].content)
    assert body["event_id"] == calls[0].headers["idempotency-key"] == result["id"]
    assert body["event_type"] == "alert" and body["schema_version"] == 1
    assert (
        body["vulnerability"]["id"] == "CVE-2026-1234"
        and body["reason"]["asset"] == "Production web"
    )
    assert "Why:" in body["message"] and FIXTURE_KEY not in json.dumps(history(configured_engine))


def test_webhook_rate_limit_preserves_event_id_and_cooldown(configured_engine, webhook_environment):
    destination = save_document(configured_engine, "connectors", config().model_dump())
    enqueue_test(configured_engine, destination["id"])
    requests = []

    def handler(request):
        requests.append(request)
        return (
            httpx.Response(429, headers={"Retry-After": "30"})
            if len(requests) == 1
            else httpx.Response(204)
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "retry"
        assert deliver_one(configured_engine, now=2000000029, client=client) is None
        assert deliver_one(configured_engine, now=2000000031, client=client)["state"] == "sent"
    assert requests[0].headers["idempotency-key"] == requests[1].headers["idempotency-key"]
    assert history(configured_engine)[0]["failures"] == 0


def test_webhook_rejects_unsafe_urls_and_redirects(monkeypatch, webhook_environment):
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request)
                or httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})
            )
        ),
        follow_redirects=True,
    ) as client:
        for url in [
            "http://example.org/alerts",
            "https://user@example.org/alerts",
            "https://example.org/alerts?secret=1",
            "https://example.org/%2e%2e/admin",
        ]:
            monkeypatch.setenv("VULNRELAY_WEBHOOK_URL", url)
            result = send_generic_webhook(
                config(), {"test": True}, "test", message_id="test", client=client
            )
            assert not result.success and not result.retryable
        assert not requests
        monkeypatch.setenv("VULNRELAY_WEBHOOK_URL", "https://receiver.example.org/alerts")
        result = send_generic_webhook(
            config(), {"test": True}, "test", message_id="test", client=client
        )
    assert not result.success and not result.retryable and len(requests) == 1


def test_webhook_private_address_requires_opt_in_and_weak_key_is_rejected(monkeypatch):
    monkeypatch.setenv("VULNRELAY_WEBHOOK_URL", "http://localhost:8080/hook")
    monkeypatch.setenv("VULNRELAY_WEBHOOK_KEY", "")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))],
    )
    get_settings.cache_clear()
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(204))) as client:
        assert not send_generic_webhook(
            config(), {"test": True}, "test", message_id="test", client=client
        ).success
        monkeypatch.setenv("VULNRELAY_WEBHOOK_ALLOW_PRIVATE_HOSTS", "true")
        get_settings.cache_clear()
        assert send_generic_webhook(
            config(), {"test": True}, "test", message_id="test", client=client
        ).success
        monkeypatch.setenv("VULNRELAY_WEBHOOK_KEY", "short")
        assert (
            "signing key"
            in send_generic_webhook(
                config(), {"test": True}, "test", message_id="test", client=client
            ).error
        )


def test_generic_webhook_requires_dedicated_environment_references(configured_engine):
    with pytest.raises(ValidationError):
        Connector(name="Bad", kind="webhook", webhook_env="TELEGRAM_BOT_TOKEN")
    fake = "-".join(("never", "echo", "this"))
    with TestClient(
        app, base_url="http://localhost", headers={"x-vulnrelay-request": "1"}
    ) as client:
        bad = client.post(
            "/api/config/connectors", json={"name": "Bad", "kind": "webhook", "webhook_env": fake}
        )
        assert bad.status_code == 422 and fake not in bad.text
        response = client.post("/api/config/connectors", json=config().model_dump())
        assert response.status_code == 201 and response.json()["kind"] == "webhook"


def test_report_payload_includes_coverage_and_dates(webhook_environment):
    report = {
        "digest": True,
        "name": "Weekly",
        "scope": "global",
        "period_start": 1,
        "period_end": 2,
        "entries": [{"id": "CVE-2026-1234"}],
        "scanned": 1,
        "candidates": 5,
        "nvd_synced": None,
    }
    captured = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: captured.append(json.loads(request.content)) or httpx.Response(204)
        )
    ) as client:
        assert send_generic_webhook(
            config(), report, "Report text", message_id="report-id", client=client
        ).success
    assert captured[0]["event_type"] == "report"
    assert captured[0]["report"]["candidates"] == 5 and captured[0]["report"]["nvd_synced"] is None
