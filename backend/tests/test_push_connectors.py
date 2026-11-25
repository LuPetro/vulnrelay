import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from pydantic import ValidationError
from test_notification_core import seed
from vulnrelay.config import get_settings
from vulnrelay.delivery import deliver_one, enqueue_test, history, send_push
from vulnrelay.pipeline import correlate
from vulnrelay.schemas import Connector
from vulnrelay.store import save_document

FIXTURE_TOKEN = "-".join(("synthetic", "push", "fixture"))


def push_config(kind="ntfy", **changes):
    prefix = kind.upper()
    return Connector.model_validate(
        {
            "name": "Push alerts",
            "kind": kind,
            "webhook_env": f"VULNRELAY_{prefix}_URL",
            "push_token_env": f"VULNRELAY_{prefix}_TOKEN",
            "ntfy_topic": "security-alerts",
            **changes,
        }
    )


@pytest.fixture
def push_environment(monkeypatch):
    for prefix in ("NTFY", "GOTIFY"):
        monkeypatch.setenv(f"VULNRELAY_{prefix}_URL", "https://push.example.org")
        monkeypatch.setenv(f"VULNRELAY_{prefix}_TOKEN", FIXTURE_TOKEN)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.parametrize("kind", ["ntfy", "gotify"])
def test_push_protocol_uses_pinned_tls_and_correct_auth(kind, push_environment):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "push.example.org"
        assert request.extensions["sni_hostname"] == "push.example.org"
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert send_push(push_config(kind), "CVE-2026-1234", client=client).success
    request = calls[0]
    body = json.loads(request.content)
    assert body["title"] == "VulnRelay" and body["message"] == "CVE-2026-1234"
    if kind == "ntfy":
        assert request.url.path == "/" and body["topic"] == "security-alerts"
        assert request.headers["authorization"] == f"Bearer {FIXTURE_TOKEN}"
    else:
        assert request.url.path == "/message" and body["priority"] == 5
        assert request.headers["x-gotify-key"] == FIXTURE_TOKEN
    assert FIXTURE_TOKEN not in str(request.url)


@pytest.mark.parametrize("kind", ["ntfy", "gotify"])
def test_push_alert_from_matching_queue_and_dedup(configured_engine, push_environment, kind):
    _, _, rule = seed(configured_engine)
    destination = save_document(configured_engine, "connectors", push_config(kind).model_dump())
    rule_id = rule.pop("id")
    save_document(
        configured_engine, "rules", {**rule, "destinations": [destination["id"]]}, rule_id
    )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(200)
        )
    ) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "sent"
    message = json.loads(requests[0].content)["message"]
    assert "CVE-2026-1234" in message and "Why:" in message
    assert FIXTURE_TOKEN not in json.dumps(history(configured_engine))


def test_ntfy_utf8_limit_and_optional_auth(monkeypatch, push_environment):
    monkeypatch.delenv("VULNRELAY_NTFY_TOKEN")
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(200)
        )
    ) as client:
        assert send_push(push_config(), "🔒" * 2000, client=client).success
    body = json.loads(requests[0].content)
    assert len(body["message"].encode("utf-8")) <= 4096
    assert body["message"].endswith("[Message truncated]")
    assert "authorization" not in requests[0].headers


def test_push_rate_limit_applies_across_topics_without_spending_failures(
    configured_engine, push_environment
):
    first = save_document(configured_engine, "connectors", push_config().model_dump())
    second = save_document(
        configured_engine,
        "connectors",
        push_config(name="Other topic", ntfy_topic="other-topic").model_dump(),
    )
    enqueue_test(configured_engine, first["id"])
    enqueue_test(configured_engine, second["id"])
    requests = []

    def handler(request):
        requests.append(request)
        return (
            httpx.Response(429, headers={"Retry-After": "30"})
            if len(requests) == 1
            else httpx.Response(200)
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "retry"
        assert deliver_one(configured_engine, now=2000000029, client=client) is None
        assert deliver_one(configured_engine, now=2000000031, client=client)["state"] == "sent"
    assert all(item["failures"] == 0 for item in history(configured_engine))


@pytest.mark.parametrize(
    "changes",
    [
        {"webhook_env": "TELEGRAM_BOT_TOKEN"},
        {"webhook_env": "VULNRELAY_GOTIFY_URL"},
        {"push_token_env": "VULNRELAY_GOTIFY_TOKEN"},
        {"ntfy_topic": "../private"},
        {"ntfy_topic": ""},
    ],
)
def test_push_schema_restricts_variable_names_and_topic(changes):
    with pytest.raises(ValidationError):
        push_config(**changes)


@pytest.mark.parametrize(("status", "retryable"), [(400, False), (403, False), (500, True)])
def test_push_classifies_provider_failures_without_echoing_response(
    status, retryable, push_environment
):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, text=FIXTURE_TOKEN))
    ) as client:
        result = send_push(push_config("gotify"), "test", client=client)
    assert not result.success and result.retryable == retryable
    assert FIXTURE_TOKEN not in result.error


def test_push_rejects_unsafe_destinations_redirects_and_credentials(monkeypatch, push_environment):
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request)
                or httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})
            )
        ),
        follow_redirects=True,
    ) as client:
        for url in (
            "http://push.example.org",
            "https://user@push.example.org",
            "https://push.example.org?secret=1",
            "https://push.example.org/%2e%2e/private",
        ):
            monkeypatch.setenv("VULNRELAY_NTFY_URL", url)
            assert not send_push(push_config(), "test", client=client).success
        assert not requests
        monkeypatch.setenv("VULNRELAY_NTFY_URL", "https://push.example.org")
        result = send_push(push_config(), "test", client=client)
        assert not result.success and not result.retryable and len(requests) == 1
        monkeypatch.setenv("VULNRELAY_NTFY_TOKEN", "bad\x01token")
        assert "invalid" in send_push(push_config(), "test", client=client).error
        monkeypatch.setenv("VULNRELAY_GOTIFY_TOKEN", "")
        assert "missing" in send_push(push_config("gotify"), "test", client=client).error


def test_ntfy_local_http_needs_explicit_private_opt_in(monkeypatch):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(
                (self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("VULNRELAY_NTFY_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("VULNRELAY_NTFY_TOKEN", "")
        monkeypatch.setenv("VULNRELAY_PUSH_ALLOW_PRIVATE_HOSTS", "false")
        get_settings.cache_clear()
        assert not send_push(push_config(), "hello").success
        monkeypatch.setenv("VULNRELAY_PUSH_ALLOW_PRIVATE_HOSTS", "true")
        get_settings.cache_clear()
        assert send_push(push_config(), "hello").success
        assert received == [
            (
                "/",
                {
                    "topic": "security-alerts",
                    "title": "VulnRelay",
                    "message": "hello",
                    "priority": 3,
                },
            )
        ]
        monkeypatch.setenv("VULNRELAY_NTFY_TOKEN", FIXTURE_TOKEN)
        assert "require HTTPS" in send_push(push_config(), "hello").error
        monkeypatch.setenv("VULNRELAY_GOTIFY_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("VULNRELAY_GOTIFY_TOKEN", FIXTURE_TOKEN)
        assert "require HTTPS" in send_push(push_config("gotify"), "hello").error
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        get_settings.cache_clear()
