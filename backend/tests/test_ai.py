import json
import socket
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_notification_core import seed
from vulnrelay import ai
from vulnrelay.api import app
from vulnrelay.config import get_settings
from vulnrelay.delivery import deliver_one, render
from vulnrelay.pipeline import correlate

NOW = 2000000000


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )


@pytest.mark.parametrize("provider", ["openai", "anthropic", "openai_compatible"])
def test_provider_protocols_send_only_source_data_and_cache_results(
    configured_engine, monkeypatch, public_dns, provider
):
    monkeypatch.setenv("VULNRELAY_AI_KEY", "example-key-not-real")
    monkeypatch.setenv("VULNRELAY_AI_BASE_URL", "https://example.org/v1")
    get_settings.cache_clear()
    config = ai.AISettings(enabled=True, provider=provider, model="vendor/model", language="German")
    ai.save_settings(configured_engine, config)
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "8.8.8.8"
        expected_host = {
            "openai": "api.openai.com",
            "anthropic": "api.anthropic.com",
            "openai_compatible": "example.org",
        }[provider]
        assert request.headers["host"] == expected_host
        assert request.extensions["sni_hostname"] == expected_host
        document = json.loads(request.content)
        assert "Secret production asset" not in json.dumps(document)
        assert "Private security team" not in json.dumps(document)
        assert "CVE-2026-1234" in json.dumps(document)
        if provider == "openai":
            assert document["store"] is False and document["max_output_tokens"] == 256
            return httpx.Response(
                200,
                json={
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "A potential issue."}],
                        }
                    ]
                },
            )
        if provider == "anthropic":
            assert request.headers["anthropic-version"] == "2026-10-21"
            return httpx.Response(
                200, json={"content": [{"type": "text", "text": "A potential issue."}]}
            )
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "A potential issue."}}]}
        )

    record = {
        "id": "CVE-2026-1234",
        "description": "Example issue.",
        "asset": "Secret production asset",
        "rule": "Private security team",
    }
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert (
            ai.summarize(configured_engine, record, now=NOW, client=client) == "A potential issue."
        )
        assert (
            ai.summarize(configured_engine, record, now=NOW, client=client) == "A potential issue."
        )
    assert len(calls) == 1
    assert ai.usage(configured_engine, NOW)["requests"] == 1


def test_disabled_ai_never_calls_provider_or_spends_budget(configured_engine, monkeypatch):
    def should_not_run(*args, **kwargs):
        raise AssertionError("disabled AI made a network call")

    monkeypatch.setattr(ai, "_provider_request", should_not_run)
    assert (
        ai.summarize(configured_engine, {"id": "CVE-2026-1234", "description": "x"}, now=NOW)
        is None
    )
    assert ai.usage(configured_engine, NOW)["requests"] == 0


def test_daily_limit_is_atomic_and_persistent(configured_engine):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: ai._reserve_request(configured_engine, 3, NOW), range(12))
        )
    assert sum(results) == 3
    assert ai.usage(configured_engine, NOW)["requests"] == 3
    assert ai._reserve_request(configured_engine, 3, NOW) is False
    assert ai._reserve_request(configured_engine, 3, NOW + 86400) is True


def test_outbound_resolution_rejects_private_and_pins_public_ip(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 11434))],
    )
    with pytest.raises(ai.AIError):
        ai._pin_endpoint("http://localhost:11434/v1/chat/completions", False)
    url, host, sni = ai._pin_endpoint("http://localhost:11434/v1/chat/completions", True)
    assert url == "http://127.0.0.1:11434/v1/chat/completions"
    assert host == "localhost:11434" and sni == "localhost"
    for address in ["169.254.169.254", "0.0.0.0", "224.0.0.1"]:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, address=address, **k: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))
            ],
        )
        with pytest.raises(ai.AIError):
            ai._pin_endpoint("http://example.org/path", True)
    for bad in [
        "https://user" + ":" + "pass@example.org/v1",
        "https://example.org/v1?token=x",
        "https://example.org/a/../private",
        "https://example.org/%2e%2e/private",
    ]:
        with pytest.raises(ai.AIError):
            ai._pin_endpoint(bad, False)


def test_api_settings_guards_secrets_and_connection_test_is_explicit(
    configured_engine, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        ai, "_provider_request", lambda *args, **kwargs: calls.append(args) or "Sample result"
    )
    headers = {"x-vulnrelay-request": "1"}
    fake_credential = "-".join(("never", "echo", "this"))
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/ai/settings").json()["settings"]["enabled"] is False
        assert client.post("/api/ai/test").status_code == 403
        bad = client.put(
            "/api/ai/settings",
            headers=headers,
            json={"model": "model", "api_key": fake_credential},
        )
        assert bad.status_code == 422 and fake_credential not in bad.text
        bad = client.put("/api/ai/settings", headers=headers, json={"enabled": True})
        assert bad.status_code == 422
        result = client.put("/api/ai/settings", headers=headers, json={"model": "custom-model"})
        assert result.status_code == 200 and result.json()["settings"]["enabled"] is False
        result = client.post("/api/ai/test", headers=headers)
        assert result.json()["ok"] is True and result.json()["summary"] == "Sample result"
        assert result.json()["usage"]["requests"] == 1 and len(calls) == 1
        assert calls[0][1]["cve"] == "TEST"
        assert fake_credential not in client.get("/api/ai/settings").text


def test_ai_failure_does_not_block_alert_delivery(configured_engine, monkeypatch):
    seed(configured_engine)
    ai.save_settings(configured_engine, ai.AISettings(enabled=True, model="model"))
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    monkeypatch.setattr(
        ai, "_provider_request", lambda *a, **k: (_ for _ in ()).throw(ai.AIError("failed"))
    )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    messages = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                messages.append(json.loads(request.content)["text"])
                or httpx.Response(200, json={"ok": True})
            )
        )
    ) as client:
        assert deliver_one(configured_engine, now=NOW, client=client)["state"] == "sent"
    assert "CVE-2026-1234" in messages[0]
    assert "AI-generated" not in messages[0]


def test_matched_alert_contains_labeled_ai_summary(configured_engine, monkeypatch):
    seed(configured_engine)
    ai.save_settings(configured_engine, ai.AISettings(enabled=True, model="model"))
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    sources = []
    monkeypatch.setattr(
        ai,
        "_provider_request",
        lambda config, source, **kwargs: sources.append(source) or "An issue is described.",
    )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    messages = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                messages.append(json.loads(request.content)["text"])
                or httpx.Response(200, json={"ok": True})
            )
        )
    ) as client:
        assert deliver_one(configured_engine, now=NOW, client=client)["state"] == "sent"
    assert sources == [{"cve": "CVE-2026-1234", "description": "Example server vulnerability"}]
    assert "AI-generated summary (unverified):\nAn issue is described." in messages[0]
    assert "Why:" in messages[0] and "Sources:" in messages[0]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"}),
        httpx.Response(503, text="secret from provider"),
        httpx.Response(200, content=b"x" * 65537),
        httpx.Response(200, json={"unexpected": []}),
    ],
)
def test_ai_provider_failures_are_bounded_and_redacted(monkeypatch, public_dns, response):
    monkeypatch.setenv("VULNRELAY_AI_KEY", "private-key-example")
    requests = []
    with (
        httpx.Client(
            transport=httpx.MockTransport(lambda request: requests.append(request) or response),
            follow_redirects=True,
        ) as client,
        pytest.raises(ai.AIError) as error,
    ):
        ai._provider_request(
            ai.AISettings(model="model"), {"cve": "TEST", "description": "example"}, client=client
        )
    assert len(requests) == 1
    assert "private-key-example" not in str(error.value)
    assert "secret from provider" not in str(error.value)


def test_migration_preserves_existing_inventory_and_queue(configured_engine):
    asset, connector, rule = seed(configured_engine)
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    command.downgrade(Config("backend/alembic.ini"), "0007")
    command.upgrade(Config("backend/alembic.ini"), "head")
    with configured_engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM assets WHERE id=:id"), {"id": asset["id"]}
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM rules WHERE id=:id"), {"id": rule["id"]}
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM outbox WHERE connector_id=:id"), {"id": connector["id"]}
            ).scalar_one()
            == 1
        )
    assert ai.settings(configured_engine).enabled is False


def test_ai_summary_is_labeled_and_respects_provider_message_limit():
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
        "match": {"confidence": "potential", "explanation": "Verify version"},
    }
    message = render(payload, max_bytes=3600, ai_summary="💥" * 10000)
    assert len(message.encode("utf-16-le")) <= 3600
    assert "AI-generated summary (unverified):" in message
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in message
