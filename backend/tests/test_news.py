import json

import httpx
import pytest
from sqlalchemy import text
from test_notification_core import seed
from vulnrelay.delivery import deliver_one, render
from vulnrelay.news import FEEDS, list_news, parse_feed, refresh, refresh_news, save_settings


def feed(*items):
    return (
        "<?xml version='1.0'?><rss><channel>"
        + "".join(
            f"<item><title>{title}</title><link>https://example.org/{slug}</link>"
            "<pubDate>Wed, 25 Nov 2026 08:00:00 GMT</pubDate></item>"
            for title, slug in items
        )
        + "</channel></rss>"
    ).encode()


def config(engine, destination, **kwargs):
    return save_settings(
        engine,
        {
            "enabled": True,
            "sources": ["cisa"],
            "notifications": True,
            "destinations": [destination],
            "categories": ["security", "vulnerability"],
            **kwargs,
        },
    )


def test_baseline_new_item_dedup_delivery_and_retry(configured_engine, monkeypatch):
    _, connector, _ = seed(configured_engine)
    config(configured_engine, connector["id"])
    responses = [
        feed(("Old security report", "old")),
        feed(("CVE-2026-9999 vulnerability", "new"), ("Old security report", "old")),
    ]
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=responses.pop(0)))
    ) as client:
        assert refresh(configured_engine, client=client, now=10)["new"] == 1
        assert refresh(configured_engine, client=client, now=20)["new"] == 1
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM outbox")).scalar_one() == 1
        raw = json.loads(connection.execute(text("SELECT payload FROM outbox")).scalar_one())
    payload, error = refresh_news(configured_engine, raw, connector["id"])
    assert error is None
    assert payload["item"]["category"] == "vulnerability"
    assert refresh_news(configured_engine, payload, connector["id"])[1] is None
    message = render(payload)
    assert "CISA Advisories" in message and "https://example.org/new" in message
    assert "AI-generated" not in message
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    sent = []

    def send(request):
        sent.append(json.loads(request.content)["text"])
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(send)) as client:
        assert deliver_one(configured_engine, now=21, client=client)["state"] == "sent"
    assert len(sent) == 1 and "CVE-2026-9999" in sent[0]
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=feed(("CVE-2026-9999 vulnerability", "new")))
        )
    ) as client:
        assert refresh(configured_engine, client=client, now=30)["new"] == 0
    assert len(list_news(configured_engine)["items"]) == 2
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM outbox")).scalar_one() == 1


def test_failed_feed_is_isolated_and_cannot_create_baseline(configured_engine):
    save_settings(configured_engine, {"enabled": True, "sources": ["cisa", "bleepingcomputer"]})

    def response(request):
        if str(request.url) == FEEDS["cisa"]["url"]:
            return httpx.Response(503)
        return httpx.Response(200, content=feed(("Cyber incident", "incident")))

    with httpx.Client(transport=httpx.MockTransport(response)) as client:
        assert refresh(configured_engine, client=client, now=10) == {
            "sources": 1,
            "new": 1,
            "failed": 1,
        }
    states = {s["id"]: s for s in list_news(configured_engine)["sources"]}
    assert states["cisa"]["last_error"] and states["bleepingcomputer"]["last_success"] == 10


def test_disabled_or_changed_subscription_cancels_pending(configured_engine):
    _, connector, _ = seed(configured_engine)
    config(configured_engine, connector["id"])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=feed(("Incident", "one")))
        )
    ) as client:
        refresh(configured_engine, client=client, now=10)
    item = list_news(configured_engine)["items"][0]
    payload = {"news": True, "news_id": item["id"]}
    config(configured_engine, connector["id"], categories=["vulnerability"])
    assert refresh_news(configured_engine, payload, connector["id"])[0] is None
    config(configured_engine, connector["id"], enabled=False)
    assert refresh_news(configured_engine, payload, connector["id"])[0] is None


def test_validate_sources_destinations_and_untrusted_feed(configured_engine):
    with pytest.raises(ValueError):
        save_settings(configured_engine, {"enabled": True, "sources": ["https://localhost/"]})
    with pytest.raises(ValueError):
        save_settings(configured_engine, {"notifications": True, "destinations": ["unknown"]})
    with pytest.raises(ValueError):
        parse_feed("cisa", b'<!DOCTYPE rss [<!ENTITY x "x">]><rss/>')
    with pytest.raises(ValueError):
        parse_feed("cisa", b"<rss/>")
    data = b"<rss><channel><item><title>Bad</title><link>javascript:alert(1)</link></item></channel></rss>"
    assert parse_feed("cisa", data) == []


def test_api_news_settings_validate_and_require_mutation_header(configured_engine):
    from fastapi.testclient import TestClient
    from vulnrelay.api import app

    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/news").json()["settings"]["enabled"] is False
        assert client.put("/api/news/settings", json={"enabled": True}).status_code == 403
        headers = {"x-vulnrelay-request": "1"}
        assert (
            client.put(
                "/api/news/settings", headers=headers, json={"sources": ["evil"]}
            ).status_code
            == 422
        )
        result = client.put(
            "/api/news/settings", headers=headers, json={"enabled": True, "sources": ["cisa"]}
        )
        assert result.status_code == 200
        assert client.get("/api/news").json()["settings"]["sources"] == ["cisa"]


def test_retry_keeps_news_identity_and_render_is_bounded(configured_engine, monkeypatch):
    _, connector, _ = seed(configured_engine)
    config(configured_engine, connector["id"])
    bodies = [feed(("Old", "old")), feed(("New zero-day vulnerability", "new"))]
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=bodies.pop(0)))
    ) as client:
        refresh(configured_engine, client=client, now=10)
        refresh(configured_engine, client=client, now=20)
    item = list_news(configured_engine)["items"][0]
    assert item["highlight"] == "Headline mentions a zero-day"
    payload, _ = refresh_news(configured_engine, {"news_id": item["id"]}, connector["id"])
    payload["item"]["title"] = "😀" * 300
    assert len(render(payload, max_bytes=2200).encode("utf-16-le")) <= 2200
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    statuses = [503, 200]
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(statuses.pop(0), json={"ok": True}))
    ) as client:
        assert deliver_one(configured_engine, now=21, client=client)["state"] == "retry"
        with configured_engine.connect() as connection:
            due = connection.execute(text("SELECT available_at FROM outbox")).scalar_one()
        assert deliver_one(configured_engine, now=due + 4, client=client)["state"] == "sent"


def test_news_webhook_uses_distinct_event_type(monkeypatch):
    import socket

    from vulnrelay.config import get_settings
    from vulnrelay.delivery import send_generic_webhook
    from vulnrelay.schemas import Connector

    monkeypatch.setenv("VULNRELAY_WEBHOOK_URL", "https://receiver.example.org/hook")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    get_settings.cache_clear()
    events = []
    payload = {
        "news": True,
        "item": {
            "title": "Example",
            "url": "https://example.org/news",
            "source_name": "CISA",
            "category": "security",
            "published": None,
        },
    }
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: events.append(json.loads(request.content)) or httpx.Response(204)
        )
    ) as client:
        result = send_generic_webhook(
            Connector(name="Webhook", kind="webhook", webhook_env="VULNRELAY_WEBHOOK_URL"),
            payload,
            render(payload),
            message_id="news-event",
            client=client,
        )
    assert result.success
    assert events[0]["event_type"] == "news" and events[0]["news"]["title"] == "Example"
    get_settings.cache_clear()


def test_monitor_checks_opted_in_news_without_blocking_other_work(configured_engine, monkeypatch):
    import vulnrelay.monitor as monitor
    from vulnrelay.config import get_settings
    from vulnrelay.monitor import cycle, set_state

    save_settings(configured_engine, {"enabled": True, "sources": ["cisa"]})
    for source in ("nvd", "cisa_kev", "epss"):
        set_state(configured_engine, f"next_{source}", 1000)
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=feed(("Vendor incident", "incident")))
        )
    ) as client:
        monkeypatch.setattr(
            monitor, "refresh_news", lambda engine: refresh(engine, client=client, now=10)
        )
        result = cycle(configured_engine, get_settings(), now=10, process_deliveries=False)
    assert result["sources"]["news"]["ok"] is True
    assert list_news(configured_engine)["items"][0]["title"] == "Vendor incident"


def test_new_sources_remain_opt_in_for_existing_and_new_installations(configured_engine):
    from vulnrelay.news import DEFAULT_SOURCES, settings

    assert settings(configured_engine).sources == list(DEFAULT_SOURCES)
    save_settings(configured_engine, {"enabled": True, "sources": ["cisa"]})
    assert settings(configured_engine).sources == ["cisa"]
    sources = {source["id"]: source for source in list_news(configured_engine)["sources"]}
    assert "cert_eu_advisories" in sources
    assert sources["cert_fr"]["type"] == "Official advisories · French"
    assert len(sources) > len(DEFAULT_SOURCES)
    item = parse_feed("cert_eu_advisories", feed(("Critical issue in Example", "issue")))[0]
    assert item["category"] == "vulnerability"


def test_new_advisory_feed_uses_feed_scope_and_silent_baseline(configured_engine, monkeypatch):
    _, connector, _ = seed(configured_engine)
    config(configured_engine, connector["id"], sources=["cert_fr"], categories=["vulnerability"])
    responses = [
        feed(("Multiples vulnérabilités dans Example", "old")),
        feed(("Multiples vulnérabilités dans Autre", "new")),
        feed(("Multiples vulnérabilités dans Autre", "new")),
    ]
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=responses.pop(0)))
    ) as client:
        assert refresh(configured_engine, client=client, now=10)["new"] == 1
        with configured_engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM outbox")).scalar_one() == 0
        assert refresh(configured_engine, client=client, now=20)["new"] == 1
        assert refresh(configured_engine, client=client, now=30)["new"] == 0
    with configured_engine.connect() as connection:
        payload = json.loads(connection.execute(text("SELECT payload FROM outbox")).scalar_one())
        assert connection.execute(text("SELECT count(*) FROM outbox")).scalar_one() == 1
    item, error = refresh_news(configured_engine, payload, connector["id"])
    assert error is None
    assert item["item"]["category"] == "vulnerability"
    assert item["item"]["source_name"] == "CERT-FR Advisories"
    assert "CERT-FR Advisories" in render(item)
