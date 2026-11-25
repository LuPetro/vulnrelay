import json
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from test_notification_core import seed
from typer.testing import CliRunner
from vulnrelay.api import app
from vulnrelay.cli import app as cli
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.delivery import deliver_one, enqueue_test, history
from vulnrelay.pipeline import correlate
from vulnrelay.queue import ClearQueue, clear_queue, queue_status
from vulnrelay.schemas import Connector
from vulnrelay.store import save_document


@pytest.fixture
def telegram(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)


def connector(engine, name="Channel", chat="-123", interval=3.1):
    return save_document(
        engine, "connectors", {"name": name, "chat_id": chat, "min_interval_seconds": interval}
    )


@pytest.mark.parametrize("value", [0, 1, 3601, float("inf"), float("nan")])
def test_invalid_pacing_is_rejected(value):
    with pytest.raises(ValidationError):
        Connector(name="test", chat_id="-123", min_interval_seconds=value)


def test_rate_limits_survive_restart_and_do_not_exhaust_failures(configured_engine, telegram):
    destination = connector(configured_engine, interval=1.1)
    message = enqueue_test(configured_engine, destination["id"])
    now = 2000000000
    responses = [httpx.Response(429, json={"parameters": {"retry_after": 2}}) for _ in range(8)] + [
        httpx.Response(200, json={"ok": True})
    ]
    calls = []

    def respond(request):
        calls.append(request)
        return responses.pop(0)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        for index in range(8):
            result = deliver_one(configured_engine, now=now + index * 3, client=client)
            assert result["state"] == "retry"
            assert deliver_one(configured_engine, now=now + index * 3 + 1, client=client) is None
        restarted = create_database_engine(str(configured_engine.url))
        try:
            snapshot = queue_status(restarted, now=now + 22)
            assert snapshot["destinations"][0]["status"] == "rate_limited"
            assert snapshot["destinations"][0]["rate_limited_until"] == now + 23
            assert deliver_one(restarted, now=now + 24, client=client)["state"] == "sent"
        finally:
            restarted.dispose()
    assert history(configured_engine)[0]["id"] == message
    assert history(configured_engine)[0]["attempts"] == 9
    assert history(configured_engine)[0]["failures"] == 0
    assert len(calls) == 9
    assert "x" * 30 not in json.dumps(queue_status(configured_engine))


def test_shared_chat_pacing_and_bot_cooldown(configured_engine, telegram):
    first = connector(configured_engine, "First", interval=3.1)
    sibling = connector(configured_engine, "Same chat", interval=1.1)
    other = connector(configured_engine, "Other chat", chat="-456")
    for item in [first, sibling, other]:
        enqueue_test(configured_engine, item["id"])
    requests = []

    def respond(request):
        requests.append(request)
        return (
            httpx.Response(429, json={"parameters": {"retry_after": 30}})
            if len(requests) == 1
            else httpx.Response(200, json={"ok": True})
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "retry"
        assert deliver_one(configured_engine, now=2000000029, client=client) is None
        snapshot = queue_status(configured_engine, now=2000000029)
        assert all(item["status"] == "rate_limited" for item in snapshot["destinations"])
        assert deliver_one(configured_engine, now=2000000031, client=client)["state"] == "sent"
        # A separate chat can proceed; same-chat aliases retain the longer 3.1-second interval.
        deliver_one(configured_engine, now=2000000031, client=client)
    assert len(requests) <= 3


def test_same_chat_aliases_cannot_bypass_pacing(configured_engine, telegram):
    for name in ["One", "Two"]:
        destination = connector(configured_engine, name)
        enqueue_test(configured_engine, destination["id"])
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
    ) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "sent"
        assert deliver_one(configured_engine, now=2000000002, client=client) is None
        assert deliver_one(configured_engine, now=2000000004, client=client)["state"] == "sent"


def test_non_rate_failures_remain_bounded(configured_engine, telegram):
    destination = connector(configured_engine)
    enqueue_test(configured_engine, destination["id"])
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
        for index in range(6):
            result = deliver_one(configured_engine, now=2000000000 + index * 4000, client=client)
            assert result["state"] == ("retry" if index < 5 else "failed")
        assert deliver_one(configured_engine, now=2000030000, client=client) is None
    assert history(configured_engine)[0]["failures"] == 6


def test_queue_summary_and_clear_are_not_history_limited(configured_engine):
    destination = connector(configured_engine)
    now = time.time()
    rows = [
        {
            "id": str(uuid4()),
            "connector": destination["id"],
            "created": now - 20,
            "state": "pending",
        }
        for _ in range(1200)
    ]
    rows += [
        {"id": str(uuid4()), "connector": destination["id"], "created": now - 10, "state": state}
        for state in ["sent", "sending", "failed", "retry"]
    ]
    rows += [
        {
            "id": str(uuid4()),
            "connector": destination["id"],
            "created": now + 10,
            "state": "pending",
        }
    ]
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO outbox (id,event_key,connector_id,payload,state,attempts,available_at,created_at)
            VALUES (:id,:id,:connector,'{}',:state,0,0,:created)"""),
            rows,
        )
    snapshot = queue_status(configured_engine)
    assert snapshot["queued"] == 1202
    assert len(history(configured_engine)) == 100
    assert clear_queue(configured_engine, ClearQueue(before=snapshot["as_of"]))["cleared"] == 1201
    result = queue_status(configured_engine)
    assert result["counts"]["sent"] == 1 and result["counts"]["sending"] == 1
    assert result["counts"]["failed"] == 1 and result["counts"]["dismissed"] == 1201
    assert result["queued"] == 1


def test_dismissal_prevents_refill_but_allows_new_material_events(configured_engine):
    seed(configured_engine)
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert clear_queue(configured_engine, ClearQueue(before=time.time()))["cleared"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    with configured_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO kev_entries (cve_id,date_added,raw) VALUES ('CVE-2026-1234','2026-11-15','{}')"
            )
        )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1


def test_clear_scope_and_api_guards(configured_engine, monkeypatch):
    first, second = connector(configured_engine, "One"), connector(configured_engine, "Two")
    for item in [first, second]:
        enqueue_test(configured_engine, item["id"])
    monkeypatch.setenv("VULNRELAY_API_TOKEN", "example-api-value")
    get_settings.cache_clear()
    try:
        with TestClient(app, base_url="http://localhost") as client:
            assert client.get("/api/queue/status").status_code == 401
            headers = {"authorization": "Bearer example-api-value"}
            snapshot = client.get("/api/queue/status", headers=headers).json()
            selection = {"before": snapshot["as_of"], "connector_id": first["id"]}
            assert (
                client.post("/api/queue/clear", headers=headers, json=selection).status_code == 403
            )
            response = client.post(
                "/api/queue/clear", headers={**headers, "x-vulnrelay-request": "1"}, json=selection
            )
            assert response.json()["cleared"] == 1
            data = client.get("/api/overview", headers=headers).json()
            assert data["deliveries"] == data["queue"]["counts"]
            assert data["queue"]["queued"] == 1
    finally:
        get_settings.cache_clear()


def test_queue_cli_requires_explicit_clear(configured_engine):
    destination = connector(configured_engine)
    enqueue_test(configured_engine, destination["id"])
    runner = CliRunner()
    assert json.loads(runner.invoke(cli, ["queue", "status"]).stdout)["queued"] == 1
    assert runner.invoke(cli, ["queue", "clear"], input="n\n").exit_code == 0
    assert queue_status(configured_engine)["queued"] == 1
    assert json.loads(runner.invoke(cli, ["queue", "clear", "--yes"]).stdout)["cleared"] == 1


def test_new_destination_cannot_bypass_existing_bot_cooldown(configured_engine, telegram):
    original = connector(configured_engine)
    enqueue_test(configured_engine, original["id"])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(429, json={"parameters": {"retry_after": 120000}})
        )
    ) as client:
        deliver_one(configured_engine, now=2000000000, client=client)
    added = connector(configured_engine, "Added later", chat="-789")
    enqueue_test(configured_engine, added["id"])

    def forbidden(request):
        raise AssertionError("A provider cooldown was bypassed")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        assert deliver_one(configured_engine, now=2000086401, client=client) is None
    assert all(
        item["rate_limited_until"] == 2000120000
        for item in queue_status(configured_engine, now=2000086401)["destinations"]
    )


def test_clear_while_sending_preserves_inflight_acknowledgement(configured_engine, telegram):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    destination = connector(configured_engine)
    for _ in range(2):
        enqueue_test(configured_engine, destination["id"])
    started, release = threading.Event(), threading.Event()

    def respond(request):
        started.set()
        assert release.wait(5)
        return httpx.Response(200, json={"ok": True})

    with (
        httpx.Client(transport=httpx.MockTransport(respond)) as client,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        sending = pool.submit(deliver_one, configured_engine, client=client)
        assert started.wait(5)
        try:
            assert deliver_one(configured_engine, client=client) is None
            assert clear_queue(configured_engine, ClearQueue(before=time.time()))["cleared"] == 1
        finally:
            release.set()
        assert sending.result(timeout=5)["state"] == "sent"
    counts = queue_status(configured_engine)["counts"]
    assert counts == {"dismissed": 1, "sent": 1}


def test_upgrade_preserves_old_queue_cooldown_and_failure_budget(configured_engine):
    from alembic import command
    from alembic.config import Config

    command.downgrade(Config("backend/alembic.ini"), "0006")
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO outbox (id,event_key,connector_id,payload,state,attempts,available_at,created_at,last_error)
            VALUES ('legacy','legacy','destination','{}','retry',9,2000000100,1,'Telegram rate limit')""")
        )
        connection.execute(
            text("INSERT INTO connector_limits (id,available_at) VALUES ('destination',2000000100)")
        )
    command.upgrade(Config("backend/alembic.ini"), "head")
    with configured_engine.connect() as connection:
        assert (
            connection.execute(text("SELECT failures FROM outbox WHERE id='legacy'")).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                text("SELECT rate_limited_until FROM connector_limits WHERE id='destination'")
            ).scalar_one()
            == 2000000100
        )


def test_history_filter_finds_failures_beyond_recent_pending_records(configured_engine):
    destination = connector(configured_engine)
    failed = enqueue_test(configured_engine, destination["id"])
    with configured_engine.begin() as connection:
        connection.execute(
            text("UPDATE outbox SET state='failed',created_at=1 WHERE id=:id"), {"id": failed}
        )
    for _ in range(101):
        enqueue_test(configured_engine, destination["id"])
    assert all(item["id"] != failed for item in history(configured_engine))
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/api/deliveries?state=failed")
        assert [item["id"] for item in response.json()] == [failed]
        assert client.get("/api/deliveries?state=invalid").status_code == 422
