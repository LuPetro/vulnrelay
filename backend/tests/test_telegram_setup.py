import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient
from vulnrelay import routes, telegram_setup
from vulnrelay.api import app
from vulnrelay.db import create_database_engine
from vulnrelay.delivery import deliver_one
from vulnrelay.telegram_setup import TelegramProbe, defer_probe, probe, reserve_probe

TOKEN = "123456:" + "x" * 30
BOT = {"id": 123456, "is_bot": True, "username": "relay_test_bot", "first_name": "Relay"}


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(telegram_setup, "_secret", lambda _: TOKEN)


def reply(request, *, updates=None, webhook=""):
    method = request.url.path.rsplit("/", 1)[-1]
    assert request.method == "POST"
    body = json.loads(request.content)
    assert "offset" not in body and "allowed_updates" not in body
    return httpx.Response(
        200,
        json={
            "ok": True,
            "result": {
                "getMe": BOT,
                "getWebhookInfo": {"url": webhook},
                "getUpdates": updates or [],
            }[method],
        },
    )


def test_missing_and_malformed_token_do_not_call_telegram(monkeypatch):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: pytest.fail("No network expected"))
    ) as client:
        for secret, code in [("", "missing_token"), ("incorrect", "invalid_token")]:
            monkeypatch.setattr(telegram_setup, "_secret", lambda _, secret=secret: secret)
            assert probe(TelegramProbe(), client=client)["code"] == code


def test_bot_check_does_not_read_updates_and_exposes_no_token(token, caplog):
    methods = []

    def handler(request):
        methods.append(request.url.path.rsplit("/", 1)[-1])
        return reply(request)

    with (
        caplog.at_level(logging.INFO),
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
    ):
        result = probe(TelegramProbe(), client=client)
    assert result["bot"]["username"] == "relay_test_bot"
    assert methods == ["getMe", "getWebhookInfo"]
    assert TOKEN not in json.dumps(result) + caplog.text


def test_discovery_extracts_only_chat_identity_without_acknowledging(token):
    private = {"id": 42, "type": "private", "first_name": "Operator"}
    updates = [
        {"message": {"chat": private, "text": "private message must not be returned"}},
        {"message": {"chat": private, "text": "another message"}},
        {"channel_post": {"chat": {"id": -10099, "type": "channel", "title": "News " + TOKEN}}},
        {"my_chat_member": {"chat": {"id": -22, "type": "group", "title": "Team"}}},
        {"edited_message": {"chat": {"id": True, "type": "private"}}},
        {"message": {"chat": {"id": 999, "type": "unexpected"}}},
        {"message": "invalid"},
        None,
    ]
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: reply(request, updates=updates))
    ) as client:
        result = probe(TelegramProbe(mode="chats"), client=client)
    assert {chat["id"] for chat in result["chats"]} == {"42", "-10099", "-22"}
    assert TOKEN not in json.dumps(result)
    assert "private message" not in json.dumps(result)
    assert "[redacted]" in json.dumps(result)


def test_active_webhook_is_preserved_and_discovery_is_skipped(token):
    methods = []

    def handler(request):
        methods.append(request.url.path.rsplit("/", 1)[-1])
        return reply(request, webhook="https://receiver.example.org/" + TOKEN)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = probe(TelegramProbe(mode="chats"), client=client)
    assert result["webhook_active"] is True and result["chats"] == []
    assert methods == ["getMe", "getWebhookInfo"]
    assert "receiver" not in json.dumps(result) and TOKEN not in json.dumps(result)


def test_empty_updates_keep_bot_verified_and_allow_manual_chat_entry(token):
    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        result = probe(TelegramProbe(mode="chats"), client=client)
    assert result["ok"] is True and result["bot"]["username"] == "relay_test_bot"
    assert result["chats"] == [] and result["webhook_active"] is False


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "invalid_token"),
        (409, "updates_busy"),
        (503, "telegram_error"),
        (302, "telegram_error"),
    ],
)
def test_upstream_errors_are_actionable_and_secret_safe(token, status, code):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, json={"ok": False, "description": TOKEN})
        )
    ) as client:
        result = probe(TelegramProbe(), client=client)
    assert result["ok"] is False and result["code"] == code
    assert TOKEN not in json.dumps(result)


def test_rate_limit_and_restart_deadline(configured_engine, token):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 120}})
        )
    ) as client:
        result = probe(TelegramProbe(), client=client)
    assert result["retry_after"] == 120
    assert reserve_probe(configured_engine, now=100) == 0
    assert reserve_probe(configured_engine, now=101) == 1
    restarted = create_database_engine(str(configured_engine.url))
    try:
        assert reserve_probe(restarted, now=101) == 1
        assert reserve_probe(restarted, now=103) == 0
        defer_probe(restarted, 120)
        assert reserve_probe(restarted) > 100
    finally:
        restarted.dispose()


def test_non_json_rate_limit_is_still_respected(token):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(429, text="Try later"))
    ) as client:
        result = probe(TelegramProbe(), client=client)
    assert result["code"] == "rate_limited" and result["retry_after"] == 60


@pytest.mark.parametrize(
    "content", [b"not json", b"[]", b"x" * (telegram_setup.MAX_RESPONSE_BYTES + 1)]
)
def test_invalid_or_oversized_responses_are_bounded(token, content):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=content))
    ) as client:
        result = probe(TelegramProbe(), client=client)
    assert result["ok"] is False


def test_transport_failure_is_secret_safe(token):
    def fail(request):
        raise httpx.ConnectError("Could not reach " + str(request.url), request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        result = probe(TelegramProbe(), client=client)
    assert result["code"] == "unavailable" and TOKEN not in json.dumps(result)


def test_setup_api_requires_security_headers_and_rate_limits(configured_engine, monkeypatch):
    calls = []
    monkeypatch.setattr(routes, "probe", lambda config: calls.append(config) or {"ok": True})
    with TestClient(app, base_url="http://localhost") as client:
        assert client.post("/api/telegram/setup/probe", json={}).status_code == 403
        headers = {"x-vulnrelay-request": "1"}
        invalid = client.post(
            "/api/telegram/setup/probe", json={"token_env": TOKEN}, headers=headers
        )
        assert invalid.status_code == 422 and TOKEN not in invalid.text
        assert (
            client.post("/api/telegram/setup/probe", json={}, headers=headers).json()["ok"] is True
        )
        assert (
            client.post("/api/telegram/setup/probe", json={}, headers=headers).json()["code"]
            == "cooldown"
        )
    assert len(calls) == 1


def test_setup_connector_test_can_be_tracked_by_message_id(configured_engine, monkeypatch):
    monkeypatch.setenv("TELEGRAM_SETUP_TOKEN", TOKEN)
    headers = {"x-vulnrelay-request": "1"}
    with TestClient(app, base_url="http://localhost", headers=headers) as client:
        connector = client.post(
            "/api/config/connectors",
            json={
                "name": "News bot",
                "kind": "telegram",
                "token_env": "TELEGRAM_SETUP_TOKEN",
                "chat_id": "42",
            },
        ).json()
        queued = client.post(f"/api/connectors/{connector['id']}/test").json()["queued"]
        response = client.get(f"/api/deliveries/{queued}")
        assert response.status_code == 200 and response.json()["state"] == "pending"
        assert "payload" not in response.json() and TOKEN not in response.text
        assert client.get("/api/deliveries/unknown").status_code == 404
        with httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
        ) as telegram:
            assert deliver_one(configured_engine, client=telegram)["state"] == "sent"
        assert client.get(f"/api/deliveries/{queued}").json()["state"] == "sent"
