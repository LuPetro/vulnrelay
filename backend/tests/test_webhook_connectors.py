import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_notification_core import seed
from vulnrelay.api import app
from vulnrelay.delivery import deliver_one, enqueue_test, history, render, send_webhook
from vulnrelay.pipeline import correlate
from vulnrelay.queue import queue_status
from vulnrelay.schemas import Connector
from vulnrelay.store import save_document


def webhook_url(kind):
    if kind == "discord":
        return "https://discord.com/api/webhooks/" + "123456789012345678/" + "x" * 40
    return "https://hooks.slack.com/services/T123456/B123456/" + "x" * 30


def connector(engine, kind, reference="WEBHOOK_TEST", name="Alerts"):
    return save_document(
        engine,
        "connectors",
        {"name": name, "kind": kind, "webhook_env": reference, "min_interval_seconds": 1.1},
    )


@pytest.mark.parametrize("kind", ["discord", "slack"])
def test_webhook_api_accepts_references_but_never_secrets(configured_engine, kind):
    with TestClient(app, base_url="http://localhost", headers={"x-vulnrelay-request": "1"}) as api:
        bad = api.post(
            "/api/config/connectors",
            json={"name": "Bad", "kind": kind, "webhook_env": webhook_url(kind)},
        )
        assert bad.status_code == 422
        assert webhook_url(kind) not in bad.text
        response = api.post(
            "/api/config/connectors",
            json={"name": "Alerts", "kind": kind, "webhook_env": "WEBHOOK_TEST"},
        )
        assert response.status_code == 201
        assert response.json()["kind"] == kind
        assert response.json()["webhook_env"] == "WEBHOOK_TEST"
        assert webhook_url(kind) not in api.get("/api/config/connectors").text


@pytest.mark.parametrize("kind", ["discord", "slack"])
def test_webhook_sends_real_matched_alert_with_evidence_and_without_mentions(
    configured_engine, monkeypatch, kind
):
    _, _, rule = seed(configured_engine)
    destination = connector(configured_engine, kind)
    rule_id = rule.pop("id")
    rule["destinations"] = [destination["id"]]
    rule["format"] = "detailed"
    save_document(configured_engine, "rules", rule, rule_id)
    monkeypatch.setenv("WEBHOOK_TEST", webhook_url(kind))
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(204) if kind == "discord" else httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "sent"
    payload = sent[0]
    content = payload["content"] if kind == "discord" else payload["text"]
    assert "CVE-2026-1234" in content
    assert "Why:" in content and "Production web" in content
    assert "Sources:" in content and "https://nvd.nist.gov/" in content
    if kind == "discord":
        assert payload["allowed_mentions"] == {"parse": []}
        assert len(content.encode("utf-16-le")) <= 4000
    else:
        assert payload["mrkdwn"] is False
    assert webhook_url(kind) not in json.dumps(history(configured_engine))
    assert webhook_url(kind) not in json.dumps(queue_status(configured_engine))


@pytest.mark.parametrize("kind", ["discord", "slack"])
def test_webhook_rate_limit_persists_across_worker_calls_and_shared_destinations(
    configured_engine, monkeypatch, kind
):
    first = connector(configured_engine, kind, name="First")
    second = connector(configured_engine, kind, name="Second")
    monkeypatch.setenv("WEBHOOK_TEST", webhook_url(kind))
    enqueue_test(configured_engine, first["id"])
    enqueue_test(configured_engine, second["id"])
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "30"})
        return httpx.Response(204) if kind == "discord" else httpx.Response(200, text="ok")

    now = 2000000000
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=now, client=client)["state"] == "retry"
        assert deliver_one(configured_engine, now=now + 29, client=client) is None
        snapshot = queue_status(configured_engine, now=now + 29)
        assert all(row["status"] == "rate_limited" for row in snapshot["destinations"])
        assert all(row["kind"] == kind for row in snapshot["destinations"])
        assert deliver_one(configured_engine, now=now + 31, client=client)["state"] == "sent"
        assert deliver_one(configured_engine, now=now + 31, client=client) is None
        assert deliver_one(configured_engine, now=now + 33, client=client)["state"] == "sent"
    assert all(row["failures"] == 0 for row in history(configured_engine))


@pytest.mark.parametrize("kind", ["discord", "slack"])
def test_webhook_rejects_nonofficial_urls_and_never_follows_redirects(monkeypatch, kind):
    settings = Connector(name="Alerts", kind=kind, webhook_env="WEBHOOK_TEST")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        for invalid in (
            "http://127.0.0.1/admin",
            webhook_url(kind).replace("https://", "http://"),
            webhook_url(kind) + "?leak=secret",
            webhook_url(kind).replace(".com/", ".com.attacker.invalid/"),
        ):
            monkeypatch.setenv("WEBHOOK_TEST", invalid)
            result = send_webhook(settings, "message", client=client)
            assert not result.success and not result.retryable
        assert not requests
        monkeypatch.setenv("WEBHOOK_TEST", webhook_url(kind))
        result = send_webhook(settings, "message", client=client)
    assert not result.success and not result.retryable and len(requests) == 1


@pytest.mark.parametrize("kind", ["discord", "slack"])
def test_webhook_transient_and_permanent_errors_do_not_expose_response(monkeypatch, kind):
    config = Connector(name="Alerts", kind=kind, webhook_env="WEBHOOK_TEST")
    monkeypatch.setenv("WEBHOOK_TEST", webhook_url(kind))
    for status, retryable in [(403, False), (503, True)]:
        with httpx.Client(
            transport=httpx.MockTransport(
                lambda _, status=status: httpx.Response(status, text=webhook_url(kind))
            )
        ) as client:
            result = send_webhook(config, "message", client=client)
        assert not result.success and result.retryable is retryable
        assert webhook_url(kind) not in result.error


def test_discord_retry_after_body_and_discord_message_limit(monkeypatch):
    config = Connector(name="Alerts", kind="discord", webhook_env="WEBHOOK_TEST")
    monkeypatch.setenv("WEBHOOK_TEST", webhook_url("discord"))
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(429, json={"retry_after": 19.5}))
    ) as client:
        assert send_webhook(config, "message", client=client).retry_after == 19.5
    payload = {
        "vulnerability": {
            "id": "CVE-2026-1234",
            "severity": "HIGH",
            "cvss": 8.0,
            "epss": None,
            "kev": False,
            "description": "💥" * 10000,
        },
        "rule": "Rule",
        "asset": "Asset",
        "format": "detailed",
        "match": {"confidence": "potential", "explanation": "Verify installed version"},
    }
    message = render(payload, max_bytes=3600)
    assert len(message.encode("utf-16-le")) <= 3600
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in message


def test_legacy_telegram_connector_still_works(configured_engine):
    # Documents created before webhook fields existed must remain valid.
    legacy = {"name": "Old Telegram", "chat_id": "-123", "enabled": True}
    with configured_engine.begin() as connection:
        connection.execute(
            text("INSERT INTO connectors (id, document) VALUES ('legacy', :document)"),
            {"document": json.dumps(legacy)},
        )
    enqueue_test(configured_engine, "legacy")
    assert queue_status(configured_engine, now=2000000000)["destinations"][0]["kind"] == "telegram"
