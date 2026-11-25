"""Real queue claims and wall-clock schedules, without external delivery credentials."""

import json
from datetime import datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from vulnrelay.api import app
from vulnrelay.db import create_database_engine
from vulnrelay.delivery import deliver_one, enqueue_test, history
from vulnrelay.delivery_schedule import next_delivery_at, schedule_allows
from vulnrelay.queue import queue_status
from vulnrelay.schemas import Connector, DeliverySchedule
from vulnrelay.store import save_document


def stamp(value):
    return datetime.fromisoformat(value).timestamp()


def schedule(days=None, start="07:00", end="17:00", timezone="Europe/Vienna"):
    return DeliverySchedule(
        timezone=timezone,
        windows=[{"days": [0, 1, 2, 3, 4] if days is None else days, "start": start, "end": end}],
    )


def destination(engine, selected=None, **values):
    return save_document(
        engine,
        "connectors",
        {"name": "Scheduled alerts", "chat_id": "-123", "delivery_schedule": selected, **values},
    )


@pytest.mark.parametrize(
    "value",
    [
        {
            "timezone": "Europe/Nowhere",
            "windows": [{"days": [0], "start": "07:00", "end": "17:00"}],
        },
        {
            "timezone": "../Europe/Vienna",
            "windows": [{"days": [0], "start": "07:00", "end": "17:00"}],
        },
        {"timezone": "UTC", "windows": []},
        {"timezone": "UTC", "windows": [{"days": [], "start": "07:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [7], "start": "07:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [True], "start": "07:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": ["1"], "start": "07:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [1, 1], "start": "07:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [0], "start": "7:00", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [0], "start": "07:00", "end": "24:00"}]},
        {"timezone": "UTC", "windows": [{"days": [0], "start": "07:60", "end": "17:00"}]},
        {"timezone": "UTC", "windows": [{"days": [0], "start": "07:00", "end": "07:00"}]},
        {"timezone": "UTC", "windows": [{"days": [0], "start": "07:00", "end": "17:00"}] * 15},
    ],
)
def test_invalid_delivery_schedule_is_rejected(value):
    with pytest.raises(ValidationError):
        Connector(name="Alerts", chat_id="-123", delivery_schedule=value)


def test_defaults_and_portable_configuration(configured_engine):
    legacy = Connector(name="Existing", chat_id="-123")
    assert legacy.delivery_schedule is None
    assert schedule_allows(None, 0) and next_delivery_at(None, 123.45) == 123.45
    selected = schedule()
    saved = destination(configured_engine, selected.model_dump())
    assert (
        Connector.model_validate({k: v for k, v in saved.items() if k != "id"}).delivery_schedule
        == selected
    )
    assert (
        json.loads(
            Connector.model_validate(
                {k: v for k, v in saved.items() if k != "id"}
            ).model_dump_json()
        )["delivery_schedule"]
        == selected.model_dump()
    )


def test_weekly_boundaries_weekends_and_non_hour_offset():
    selected = schedule()
    assert schedule_allows(selected, stamp("2027-01-04T07:00:00+01:00"))
    assert schedule_allows(selected, stamp("2027-01-04T16:59:59.999+01:00"))
    assert not schedule_allows(selected, stamp("2027-01-04T17:00:00+01:00"))
    assert next_delivery_at(selected, stamp("2027-01-08T17:00:00+01:00")) == stamp(
        "2027-01-11T07:00:00+01:00"
    )
    kathmandu = schedule(timezone="Asia/Kathmandu")
    assert next_delivery_at(kathmandu, stamp("2027-01-04T00:00:00+00:00")) == stamp(
        "2027-01-04T07:00:00+05:45"
    )


def test_overnight_windows_are_anchored_to_the_start_day():
    selected = schedule(days=[4], start="22:00", end="02:00")
    assert not schedule_allows(selected, stamp("2027-01-08T01:00:00+01:00"))
    assert schedule_allows(selected, stamp("2027-01-08T22:00:00+01:00"))
    assert schedule_allows(selected, stamp("2027-01-09T01:59:59+01:00"))
    assert not schedule_allows(selected, stamp("2027-01-09T02:00:00+01:00"))
    assert next_delivery_at(selected, stamp("2027-01-09T02:00:00+01:00")) == stamp(
        "2027-01-15T22:00:00+01:00"
    )
    sunday = schedule(days=[6], start="23:00", end="01:00")
    assert schedule_allows(sunday, stamp("2027-01-04T00:30:00+01:00"))


def test_multiple_overlapping_and_split_windows():
    selected = DeliverySchedule(
        timezone="UTC",
        windows=[
            {"days": [0], "start": "07:00", "end": "10:00"},
            {"days": [0], "start": "09:00", "end": "12:00"},
            {"days": [0], "start": "13:00", "end": "17:00"},
        ],
    )
    assert schedule_allows(selected, stamp("2027-01-04T11:00:00+00:00"))
    assert next_delivery_at(selected, stamp("2027-01-04T12:00:00+00:00")) == stamp(
        "2027-01-04T13:00:00+00:00"
    )


@pytest.mark.parametrize(
    "selected,current,expected",
    [
        (schedule([6], "02:30", "04:00"), "2027-03-28T01:55:00+01:00", "2027-03-28T03:00:00+02:00"),
        (schedule([6], "02:10", "02:40"), "2027-03-28T01:55:00+01:00", "2027-04-04T02:10:00+02:00"),
        (schedule([6], "01:00", "02:30"), "2027-10-31T02:50:00+02:00", "2027-10-31T02:00:00+01:00"),
        (schedule([6], "02:15", "02:45"), "2027-10-31T02:50:00+02:00", "2027-10-31T02:15:00+01:00"),
        (
            schedule([6], "02:10", "03:00", "Australia/Lord_Howe"),
            "2027-10-03T01:55:00+10:30",
            "2027-10-03T02:30:00+11:00",
        ),
        (
            schedule([6], "01:00", "01:45", "Australia/Lord_Howe"),
            "2027-04-04T01:50:00+11:00",
            "2027-04-04T01:30:00+10:30",
        ),
    ],
)
def test_dst_gaps_and_repeated_hours_use_real_local_windows(selected, current, expected):
    result = next_delivery_at(selected, stamp(current))
    assert result == stamp(expected)
    assert schedule_allows(selected, result)
    assert not schedule_allows(selected, result - 0.001)


def test_both_folds_of_an_ambiguous_window_are_eligible():
    selected = schedule([6], "02:15", "02:45")
    assert schedule_allows(selected, stamp("2027-10-31T02:20:00+02:00"))
    assert schedule_allows(selected, stamp("2027-10-31T02:20:00+01:00"))
    assert not schedule_allows(selected, stamp("2027-10-31T02:50:00+02:00"))
    assert not schedule_allows(selected, stamp("2027-10-31T02:50:00+01:00"))


def test_off_hours_do_not_claim_attempt_or_reserve_pacing_and_survive_restart(
    configured_engine, monkeypatch
):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    saved = destination(configured_engine, schedule().model_dump())
    message = enqueue_test(configured_engine, saved["id"])
    outside = stamp("2027-01-08T18:00:00+01:00")
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        assert deliver_one(configured_engine, now=outside, client=client) is None
        assert requests == []
        row = history(configured_engine)[0]
        assert row["id"] == message and row["state"] == "pending"
        assert row["attempts"] == row["failures"] == 0
        with configured_engine.connect() as connection:
            assert (
                connection.execute(text("SELECT COUNT(*) FROM connector_limits")).scalar_one() == 0
            )
        resumed = stamp("2027-01-11T07:00:00+01:00")
        status = queue_status(configured_engine, now=outside)
        assert status["ready"] == 0 and status["queued"] == 1
        detail = status["destinations"][0]
        assert detail["status"] == "outside_schedule"
        assert detail["schedule_timezone"] == "Europe/Vienna"
        assert detail["schedule_resume_at"] == detail["next_attempt_at"] == resumed
        restarted = create_database_engine(str(configured_engine.url))
        try:
            assert deliver_one(restarted, now=resumed - 0.01, client=client) is None
            assert deliver_one(restarted, now=resumed, client=client)["state"] == "sent"
        finally:
            restarted.dispose()
    assert len(requests) == 1


def test_provider_deadline_is_combined_with_next_open_window(configured_engine, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    saved = destination(configured_engine, schedule().model_dump())
    enqueue_test(configured_engine, saved["id"])
    now = stamp("2027-01-08T16:59:00+01:00")
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(429, json={"parameters": {"retry_after": 3600}})
        )
    ) as client:
        assert deliver_one(configured_engine, now=now, client=client)["state"] == "retry"
        assert deliver_one(configured_engine, now=now + 3601, client=client) is None
    resumed = stamp("2027-01-11T07:00:00+01:00")
    status = queue_status(configured_engine, now=now + 600)["destinations"][0]
    assert status["status"] == "rate_limited"
    assert status["next_attempt_at"] == status["schedule_resume_at"] == resumed
    assert (
        queue_status(configured_engine, now=now + 3601)["destinations"][0]["status"]
        == "outside_schedule"
    )
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
    ) as client:
        assert deliver_one(configured_engine, now=resumed, client=client)["state"] == "sent"
    row = history(configured_engine)[0]
    assert row["attempts"] == 2 and row["failures"] == 0


def test_schedule_edit_releases_waiting_message_immediately(configured_engine, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    saved = destination(configured_engine, schedule().model_dump())
    enqueue_test(configured_engine, saved["id"])
    now = stamp("2027-01-09T10:00:00+01:00")
    assert deliver_one(configured_engine, now=now) is None
    save_document(
        configured_engine,
        "connectors",
        {k: v for k, v in saved.items() if k not in {"id", "delivery_schedule"}},
        saved["id"],
    )
    assert queue_status(configured_engine, now=now)["destinations"][0]["status"] == "ready"
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
    ) as client:
        assert deliver_one(configured_engine, now=now, client=client)["state"] == "sent"


def test_schedule_is_rechecked_after_alert_revalidation(configured_engine, monkeypatch):
    import vulnrelay.delivery as delivery

    saved = destination(configured_engine, schedule().model_dump())
    enqueue_test(configured_engine, saved["id"])
    now = stamp("2027-01-04T10:00:00+01:00")

    def edit_while_refreshing(engine, payload, connector_id):
        save_document(
            engine,
            "connectors",
            {
                **{k: v for k, v in saved.items() if k != "id"},
                "delivery_schedule": schedule([1]).model_dump(),
            },
            connector_id,
        )
        return payload, None

    monkeypatch.setattr(delivery, "refresh_alert", edit_while_refreshing)
    assert deliver_one(configured_engine, now=now) is None
    row = history(configured_engine)[0]
    assert row["state"] == "pending" and row["attempts"] == row["failures"] == 0
    with configured_engine.connect() as connection:
        assert (
            connection.execute(text("SELECT MAX(available_at) FROM connector_limits")).scalar_one()
            <= now
        )
    assert (
        queue_status(configured_engine, now=now)["destinations"][0]["status"] == "outside_schedule"
    )


@pytest.mark.parametrize("invalid", [False, True])
def test_disabled_or_invalid_connectors_still_reach_failure_inspection(configured_engine, invalid):
    saved = destination(configured_engine, schedule().model_dump(), enabled=False)
    enqueue_test(configured_engine, saved["id"])
    if invalid:
        with configured_engine.begin() as connection:
            connection.execute(
                text("UPDATE connectors SET document=:document WHERE id=:id"),
                {
                    "id": saved["id"],
                    "document": json.dumps(
                        {
                            "name": "Broken",
                            "chat_id": "invalid",
                            "delivery_schedule": schedule().model_dump(),
                        }
                    ),
                },
            )
    assert (
        deliver_one(configured_engine, now=stamp("2027-01-09T10:00:00+01:00"))["state"] == "failed"
    )


def test_connector_api_roundtrip_and_invalid_schedule_guards(configured_engine):
    with TestClient(app, base_url="http://localhost") as client:
        headers = {"x-vulnrelay-request": "1"}
        response = client.post(
            "/api/config/connectors",
            headers=headers,
            json={
                "name": "Office",
                "chat_id": "-123",
                "delivery_schedule": schedule().model_dump(),
            },
        )
        assert response.status_code == 201
        saved = response.json()
        assert (
            client.get("/api/config/connectors").json()[0]["delivery_schedule"]
            == schedule().model_dump()
        )
        assert (
            client.put(
                "/api/config/connectors/" + saved["id"],
                headers=headers,
                json={
                    "name": "Office",
                    "chat_id": "-123",
                    "delivery_schedule": {"timezone": "UTC", "windows": []},
                },
            ).status_code
            == 422
        )


def test_oldest_offhours_destination_does_not_block_other_connectors(
    configured_engine, monkeypatch
):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    blocked = destination(configured_engine, schedule().model_dump())
    waiting = enqueue_test(configured_engine, blocked["id"])
    free = destination(configured_engine, None, name="Always on", chat_id="-456")
    sendable = enqueue_test(configured_engine, free["id"])
    now = stamp("2027-01-09T10:00:00+01:00")
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
    ) as client:
        result = deliver_one(configured_engine, now=now, client=client)
    assert result["id"] == sendable and result["state"] == "sent"
    rows = {row["id"]: row for row in history(configured_engine)}
    assert rows[waiting]["attempts"] == 0 and rows[waiting]["state"] == "pending"


def test_window_closing_during_revalidation_defers_without_an_attempt(
    configured_engine, monkeypatch
):
    import vulnrelay.delivery as delivery

    saved = destination(configured_engine, schedule().model_dump())
    enqueue_test(configured_engine, saved["id"])
    before_close = stamp("2027-01-04T16:59:59+01:00")
    after_close = stamp("2027-01-04T17:00:00+01:00")
    monkeypatch.setattr(delivery.time, "time", lambda: before_close)

    def cross_boundary(engine, payload, connector_id):
        monkeypatch.setattr(delivery.time, "time", lambda: after_close)
        return payload, None

    monkeypatch.setattr(delivery, "refresh_alert", cross_boundary)
    assert deliver_one(configured_engine) is None
    row = history(configured_engine)[0]
    assert row["attempts"] == row["failures"] == 0 and row["state"] == "pending"
    assert queue_status(configured_engine)["destinations"][0]["next_attempt_at"] == stamp(
        "2027-01-05T07:00:00+01:00"
    )


def test_cooldown_ending_after_current_window_waits_until_the_following_day(configured_engine):
    saved = destination(configured_engine, schedule().model_dump())
    enqueue_test(configured_engine, saved["id"])
    now = stamp("2027-01-04T10:00:00+01:00")
    until = stamp("2027-01-04T18:00:00+01:00")
    with configured_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO connector_limits(id,available_at,rate_limited_until) VALUES(:id,:until,:until)"
            ),
            {"id": saved["id"], "until": until},
        )
    status = queue_status(configured_engine, now=now)["destinations"][0]
    assert status["status"] == "rate_limited" and status["schedule_resume_at"] is None
    assert status["next_attempt_at"] == stamp("2027-01-05T07:00:00+01:00")


@pytest.mark.parametrize(
    ("schedule", "message"),
    [
        (
            {
                "timezone": "private/invalid_zone",
                "windows": [{"days": [0], "start": "07:00", "end": "17:00"}],
            },
            "valid IANA time zone",
        ),
        (
            {"timezone": "UTC", "windows": [{"days": [], "start": "07:00", "end": "17:00"}]},
            "choose weekdays",
        ),
    ],
)
def test_schedule_api_returns_actionable_safe_validation(configured_engine, schedule, message):
    with TestClient(app, base_url="http://localhost") as client:
        response = client.post(
            "/api/config/connectors",
            headers={"x-vulnrelay-request": "1"},
            json={"name": "Invalid schedule", "chat_id": "-123456", "delivery_schedule": schedule},
        )
        assert response.status_code == 422
        assert message in response.json()["detail"]
        assert "private/invalid_zone" not in response.text
        assert client.get("/api/config/connectors").json() == []
