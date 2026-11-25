import json
import smtplib
import socket
import ssl

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_notification_core import seed
from vulnrelay import delivery
from vulnrelay.api import app
from vulnrelay.config import get_settings
from vulnrelay.delivery import deliver_one, enqueue_test, history, send_smtp
from vulnrelay.pipeline import correlate
from vulnrelay.schemas import Connector
from vulnrelay.store import save_document

FIXTURE_CREDENTIAL = "-".join(("fake", "test", "value"))


@pytest.fixture
def smtp_environment(monkeypatch):
    monkeypatch.setenv("VULNRELAY_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("VULNRELAY_SMTP_PORT", "587")
    monkeypatch.setenv("VULNRELAY_SMTP_USER", "test-user")
    monkeypatch.setenv("VULNRELAY_SMTP_PASSWORD", FIXTURE_CREDENTIAL)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 587))],
    )
    get_settings.cache_clear()


def config():
    return Connector(
        name="Email alerts", kind="smtp", smtp_from="alerts@example.org", smtp_to="team@example.org"
    )


def test_smtp_delivery_uses_pinned_tls_and_preserves_evidence(
    configured_engine, monkeypatch, smtp_environment
):
    _, _, rule = seed(configured_engine)
    destination = save_document(configured_engine, "connectors", config().model_dump())
    identifier = rule.pop("id")
    save_document(
        configured_engine, "rules", {**rule, "destinations": [destination["id"]]}, identifier
    )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    calls = []

    class FakeSMTP:
        def __init__(self, host, address, port):
            calls.append(("connect", host, address, port))

        def ehlo_or_helo_if_needed(self):
            calls.append(("ehlo",))

        def starttls(self, *, context):
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            calls.append(("tls",))

        def login(self, username, password):
            assert username == "test-user" and password == FIXTURE_CREDENTIAL
            calls.append(("authenticated",))

        def send_message(self, message):
            calls.append(("message", message))
            return {}

        def quit(self):
            calls.append(("quit",))

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(delivery, "_PinnedSMTP", FakeSMTP)
    result = deliver_one(configured_engine, now=2000000000)
    assert result["state"] == "sent"
    assert calls[:3] == [("connect", "smtp.example.org", "8.8.8.8", 587), ("ehlo",), ("tls",)]
    message = next(item[1] for item in calls if item[0] == "message")
    assert message["To"] == "team@example.org" and message["From"] == "alerts@example.org"
    assert "CVE-2026-1234" in message.get_content() and "Why:" in message.get_content()
    assert "Sources:" in message.get_content() and message["Message-ID"].endswith(
        "@vulnrelay.local>"
    )
    assert FIXTURE_CREDENTIAL not in json.dumps(history(configured_engine))


@pytest.mark.parametrize(
    ("exception", "retryable"),
    [
        (smtplib.SMTPResponseException(421, b"temporary secret details"), True),
        (smtplib.SMTPResponseException(550, b"permanent secret details"), False),
        (smtplib.SMTPNotSupportedError("provider details"), False),
        (ssl.SSLCertVerificationError("provider details"), False),
        (TimeoutError("provider details"), True),
    ],
)
def test_smtp_failures_are_classified_without_exposing_secrets(
    monkeypatch, smtp_environment, exception, retryable
):
    class FailingSMTP:
        def __init__(self, *args):
            pass

        def ehlo_or_helo_if_needed(self):
            pass

        def starttls(self, *, context):
            raise exception

        def close(self):
            pass

    monkeypatch.setattr(delivery, "_PinnedSMTP", FailingSMTP)
    outcome = send_smtp(config(), "message", message_id="test")
    assert not outcome.success and outcome.retryable is retryable
    assert FIXTURE_CREDENTIAL not in outcome.error and "provider details" not in outcome.error


def test_smtp_transient_failure_retries_in_persistent_queue(
    configured_engine, monkeypatch, smtp_environment
):
    destination = save_document(configured_engine, "connectors", config().model_dump())
    enqueue_test(configured_engine, destination["id"])
    attempts = []

    class FlakySMTP:
        def __init__(self, *args):
            pass

        def ehlo_or_helo_if_needed(self):
            pass

        def starttls(self, *, context):
            pass

        def login(self, username, password):
            pass

        def send_message(self, message):
            attempts.append(message)
            if len(attempts) == 1:
                raise smtplib.SMTPResponseException(421, b"temporary")
            return {}

        def quit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(delivery, "_PinnedSMTP", FlakySMTP)
    first = deliver_one(configured_engine, now=2000000000)
    assert first["state"] == "retry" and first["attempts"] == 1
    assert deliver_one(configured_engine, now=2000000001) is None
    assert deliver_one(configured_engine, now=2000000031)["state"] == "sent"
    assert len(attempts) == 2


def test_smtp_rejects_private_hosts_by_default_and_never_sends_credentials(monkeypatch):
    monkeypatch.setenv("VULNRELAY_SMTP_HOST", "localhost")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 587))],
    )
    monkeypatch.setattr(
        delivery, "_PinnedSMTP", lambda *a: pytest.fail("private connection was attempted")
    )
    get_settings.cache_clear()
    result = send_smtp(config(), "message", message_id="test")
    assert not result.success and "not permitted" in result.error
    monkeypatch.setenv("VULNRELAY_SMTP_HOST", "smtp.example.org/path")
    assert "invalid" in send_smtp(config(), "message", message_id="test").error


def test_smtp_rejects_invalid_authentication_before_connecting(monkeypatch, smtp_environment):
    monkeypatch.setenv("VULNRELAY_SMTP_USER", "user-ü")
    monkeypatch.setattr(
        delivery, "_PinnedSMTP", lambda *a: pytest.fail("invalid credentials connected")
    )
    outcome = send_smtp(config(), "message", message_id="test")
    assert not outcome.success and "authentication" in outcome.error


def test_private_smtp_requires_explicit_opt_in_and_still_uses_tls(monkeypatch):
    monkeypatch.setenv("VULNRELAY_SMTP_HOST", "localhost")
    monkeypatch.setenv("VULNRELAY_SMTP_ALLOW_PRIVATE_HOSTS", "true")
    monkeypatch.setenv("VULNRELAY_SMTP_USER", "")
    monkeypatch.setenv("VULNRELAY_SMTP_PASSWORD", "")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 587))],
    )
    get_settings.cache_clear()
    calls = []

    class LocalSMTP:
        def __init__(self, host, address, port):
            calls.append((host, address, port))

        def ehlo_or_helo_if_needed(self):
            pass

        def starttls(self, *, context):
            calls.append(("tls", context.check_hostname))

        def send_message(self, message):
            return {}

        def quit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(delivery, "_PinnedSMTP", LocalSMTP)
    assert send_smtp(config(), "message", message_id="test").success
    assert calls == [("localhost", "127.0.0.1", 587), ("tls", True)]


def test_pinned_smtp_keeps_hostname_for_certificate_verification(monkeypatch):
    # Exercise the real SMTP.connect path: Python 3.13 sets _host there,
    # while Python 3.12 sets it during initialization.
    monkeypatch.setattr(smtplib.SMTP, "getreply", lambda self: (220, b"ready"))
    captured = []
    monkeypatch.setattr(
        socket, "create_connection", lambda address, timeout: captured.append(address)
    )
    smtp = delivery._PinnedSMTP("smtp.example.org", "8.8.8.8", 587)
    assert smtp._host == "smtp.example.org" and captured == [("8.8.8.8", 587)]


@pytest.mark.parametrize(
    "address", ["", "bad", "team@example.org\nBcc:evil@example.org", "a@example.org,b@example.org"]
)
def test_smtp_rejects_invalid_addresses_and_header_injection(address):
    with pytest.raises(ValidationError):
        Connector(name="invalid", kind="smtp", smtp_from="alerts@example.org", smtp_to=address)


def test_api_smtp_credentials_must_be_server_environment_references(configured_engine):
    with TestClient(
        app, base_url="http://localhost", headers={"x-vulnrelay-request": "1"}
    ) as client:
        payload = config().model_dump()
        fake_credential = "-".join(("never", "echo", "this"))
        bad = client.post("/api/config/connectors", json={**payload, "password": fake_credential})
        assert bad.status_code == 422 and fake_credential not in bad.text
        response = client.post("/api/config/connectors", json=payload)
        assert (
            response.status_code == 201
            and response.json()["smtp_password_env"] == config().smtp_password_env
        )
