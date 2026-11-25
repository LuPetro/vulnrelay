import json

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import text
from vulnrelay.delivery import deliver_one, enqueue_test, history, render, retry_failed
from vulnrelay.matching import match
from vulnrelay.monitor import cycle, monitor_lock, state
from vulnrelay.pipeline import correlate
from vulnrelay.rules import evaluate
from vulnrelay.schemas import Asset, Condition, Group, Rule
from vulnrelay.store import delete_document, list_documents, save_document

CPE = "cpe:2.3:a:example:server:1.2.3:*:*:*:*:*:*:*"


def seed(engine):
    raw = {
        "id": "CVE-2026-1234",
        "configurations": [
            {"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": CPE}]}]}
        ],
    }
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities (id,modified,description,status,cvss_score,severity,nvd_raw)
            VALUES ('CVE-2026-1234','2026-11-12','Example server vulnerability','Analyzed',9.8,'CRITICAL',:raw)"""),
            {"raw": json.dumps(raw)},
        )
    asset = save_document(
        engine,
        "assets",
        {
            "name": "Production web",
            "kind": "vendor_product",
            "vendor": "example",
            "product": "server",
            "group": "production",
        },
    )
    connector = save_document(
        engine, "connectors", {"name": "Security Telegram", "chat_id": "-123456"}
    )
    rule = save_document(
        engine,
        "rules",
        {
            "name": "Critical production",
            "groups": ["production"],
            "destinations": [connector["id"]],
            "condition": {
                "kind": "any",
                "children": [
                    {"kind": "condition", "field": "cvss", "op": "gte", "value": 9},
                    {"kind": "condition", "field": "kev", "op": "eq", "value": True},
                ],
            },
        },
    )
    return asset, connector, rule


def test_nested_logic_keeps_missing_metrics_unknown():
    node = Group.model_validate(
        {
            "kind": "not",
            "children": [{"kind": "condition", "field": "epss", "op": "gte", "value": 0.7}],
        }
    )
    assert evaluate(node, {"epss": None})["result"] is None
    assert evaluate(node, {"epss": 0.8})["result"] is False
    with pytest.raises(ValidationError):
        Condition(field="epss", op="gte", value=True)
    with pytest.raises(ValidationError):
        Condition(field="kev", op="eq", value="false")


def test_matching_never_confirms_keyword_or_version_range():
    asset = Asset(name="Server", kind="cpe", cpe=CPE)
    leaf = {"vulnerable": True, "criteria": CPE}
    cve = {
        "status": "Analyzed",
        "description": "server issue",
        "nvd": {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [leaf]}]}]},
    }
    assert match(asset, cve)["confidence"] == "confirmed"
    leaf["versionStartIncluding"] = "1.0"
    assert match(asset, cve)["confidence"] == "unknown"
    del leaf["versionStartIncluding"]
    cve["nvd"]["configurations"][0]["operator"] = "AND"
    assert match(asset, cve)["confidence"] != "confirmed"
    keyword = Asset(name="keyword", kind="keyword", keyword="server")
    assert match(keyword, cve)["confidence"] == "potential"
    cve["description"] = "serverless issue"
    assert match(keyword, cve) is None
    cve["status"] = "Rejected"
    assert match(asset, cve) is None


def test_conflicting_cpe_versions_are_rejected_and_never_confirmed(configured_engine, caplog):
    asset, _, _ = seed(configured_engine)
    document = {"name": "Conflicting server", "kind": "cpe", "cpe": CPE, "version": "2.0"}
    with pytest.raises(ValidationError, match="version conflicts"):
        save_document(configured_engine, "assets", document)
    cve = {
        "status": "Analyzed",
        "nvd": {"configurations": [{"cpeMatch": [{"vulnerable": True, "criteria": CPE}]}]},
    }
    # Protect unchecked models and already persisted documents from older installations.
    assert match(Asset.model_construct(**document), cve) is None
    with configured_engine.begin() as connection:
        connection.execute(
            text("INSERT INTO assets (id,document) VALUES ('legacy',:document)"),
            {"document": json.dumps(document)},
        )
    reports = correlate(configured_engine)["reports"]
    assert [row["asset_id"] for row in reports] == [asset["id"]]
    assert "Skipping invalid asset configuration" in caplog.text


@pytest.mark.parametrize(
    ("component", "version", "confidence"),
    [
        ("1.2.3", "1.2.3", "confirmed"),
        (r"1.2.3\+build", "1.2.3+build", "confirmed"),
        ("*", "1.2.3", "unknown"),
    ],
)
def test_consistent_cpe_versions_preserve_conservative_matching(component, version, confidence):
    cpe = CPE.replace(":1.2.3:", f":{component}:")
    asset = Asset(name="Server", kind="cpe", cpe=cpe, version=version)
    cve = {"nvd": {"configurations": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}}
    assert match(asset, cve)["confidence"] == confidence


@pytest.mark.parametrize("queue_state", ["pending", "retry", "sending"])
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("rule_disabled", "Rule disabled"),
        ("rule_removed", "Rule disabled or removed"),
        ("asset_disabled", "Asset disabled"),
        ("asset_removed", "Asset disabled or removed"),
        ("condition_changed", "no longer matches"),
        ("group_changed", "no longer matches"),
        ("identity_changed", "no longer matches"),
        ("selection_changed", "no longer matches"),
        ("destination_removed", "Destination removed"),
        ("cve_rejected", "no longer matches"),
        ("cve_removed", "no longer available"),
        ("legacy_version_conflict", "configuration is invalid"),
    ],
)
def test_obsolete_alerts_are_cancelled_before_http_delivery(
    configured_engine, monkeypatch, queue_state, change, reason
):
    asset, connector, rule = seed(configured_engine)
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    with configured_engine.begin() as connection:
        connection.execute(
            text("UPDATE outbox SET state=:state, attempts=1, available_at=0, lease_until=1"),
            {"state": queue_state},
        )
    asset_id, rule_id = asset.pop("id"), rule.pop("id")
    if change == "rule_disabled":
        save_document(configured_engine, "rules", {**rule, "enabled": False}, rule_id)
    elif change == "rule_removed":
        delete_document(configured_engine, "rules", rule_id)
    elif change == "asset_disabled":
        save_document(configured_engine, "assets", {**asset, "enabled": False}, asset_id)
    elif change == "asset_removed":
        delete_document(configured_engine, "assets", asset_id)
    elif change == "condition_changed":
        condition = {"kind": "condition", "field": "epss", "op": "gte", "value": 0.9}
        save_document(configured_engine, "rules", {**rule, "condition": condition}, rule_id)
    elif change == "group_changed":
        save_document(configured_engine, "assets", {**asset, "group": "other"}, asset_id)
    elif change == "identity_changed":
        save_document(configured_engine, "assets", {**asset, "product": "other"}, asset_id)
    elif change == "selection_changed":
        other = save_document(configured_engine, "assets", {**asset, "name": "Other asset"})
        save_document(configured_engine, "rules", {**rule, "assets": [other["id"]]}, rule_id)
    elif change == "destination_removed":
        other = save_document(configured_engine, "connectors", {"name": "Other", "chat_id": "-1"})
        save_document(configured_engine, "rules", {**rule, "destinations": [other["id"]]}, rule_id)
    elif change == "cve_rejected":
        with configured_engine.begin() as connection:
            connection.execute(text("UPDATE vulnerabilities SET status='Rejected'"))
    elif change == "cve_removed":
        with configured_engine.begin() as connection:
            connection.execute(text("DELETE FROM vulnerabilities"))
    elif change == "legacy_version_conflict":
        with configured_engine.begin() as connection:
            connection.execute(
                text("UPDATE assets SET document=:document WHERE id=:id"),
                {
                    "id": asset_id,
                    "document": json.dumps({**asset, "kind": "cpe", "cpe": CPE, "version": "2.0"}),
                },
            )
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)

    def unexpected_send(request):
        pytest.fail("An obsolete alert reached the Telegram HTTP adapter")

    with httpx.Client(transport=httpx.MockTransport(unexpected_send)) as client:
        outcome = deliver_one(configured_engine, now=2000000000, client=client)
        assert outcome["state"] == "cancelled"
        assert reason in outcome["error"]
        assert deliver_one(configured_engine, now=2000004000, client=client) is None
    row = history(configured_engine)[0]
    assert row["connector_id"] == connector["id"] and row["sent_at"] is None
    assert row["state"] == "cancelled" and reason in row["last_error"]
    assert retry_failed(configured_engine, row["id"]) is False


def test_reenabled_rule_can_requeue_cancelled_alert_without_duplicate_delivery(
    configured_engine, monkeypatch
):
    _, _, rule = seed(configured_engine)
    rule_id = rule.pop("id")
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    save_document(configured_engine, "rules", {**rule, "enabled": False}, rule_id)
    assert deliver_one(configured_engine, now=2000000000)["state"] == "cancelled"
    save_document(configured_engine, "rules", rule, rule_id)
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=2000000002, client=client)["state"] == "sent"
        assert deliver_one(configured_engine, now=2000000004, client=client) is None
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    assert len(sent) == len(history(configured_engine)) == 1


def test_delivery_uses_current_matching_data_and_rule_format(configured_engine, monkeypatch):
    asset, _, rule = seed(configured_engine)
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    asset_id, rule_id = asset.pop("id"), rule.pop("id")
    save_document(configured_engine, "assets", {**asset, "name": "Renamed server"}, asset_id)
    save_document(configured_engine, "rules", {**rule, "format": "detailed"}, rule_id)
    with configured_engine.begin() as connection:
        connection.execute(
            text("UPDATE vulnerabilities SET description='Updated source description'")
        )
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    sent = []

    def handler(request):
        sent.append(json.loads(request.content)["text"])
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_one(configured_engine, now=2000000000, client=client)["state"] == "sent"
    assert "Renamed server" in sent[0] and "Updated source description" in sent[0]
    with configured_engine.connect() as connection:
        payload = json.loads(connection.execute(text("SELECT payload FROM outbox")).scalar_one())
    assert payload["asset"] == "Renamed server" and payload["format"] == "detailed"


def test_pipeline_queue_dedup_and_material_change(configured_engine):
    _asset, _connector, rule = seed(configured_engine)
    dry = correlate(configured_engine)
    assert dry["queued"] == 0
    assert dry["reports"][0]["matched"] is True
    assert dry["reports"][0]["match"]["confidence"] == "potential"
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert correlate(configured_engine, enqueue=True)["queued"] == 0
    with configured_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO kev_entries (cve_id,date_added,raw) VALUES ('CVE-2026-1234','2026-11-12','{}')"
            )
        )
    assert correlate(configured_engine, enqueue=True)["queued"] == 1
    assert len(history(configured_engine)) == 2
    rule.pop("id")
    rule["condition"] = {"kind": "condition", "field": "epss", "op": "gte", "value": 0.9}
    save_document(configured_engine, "rules", rule, "missing-metric-rule")
    assert (
        correlate(configured_engine, rule_id="missing-metric-rule")["reports"][0]["matched"]
        is False
    )


def test_delivery_retries_survive_a_new_worker_and_hide_secrets(configured_engine, monkeypatch):
    _, connector, _ = seed(configured_engine)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "x" * 30)
    message_id = enqueue_test(configured_engine, connector["id"])
    responses = [
        httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 90}}),
        httpx.Response(200, json={"ok": True}),
    ]
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return responses.pop(0)

    now = 2000000000
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        first = deliver_one(configured_engine, now=now, client=client)
        assert first["id"] == message_id and first["state"] == "retry"
        assert deliver_one(configured_engine, now=now + 1, client=client) is None
        second = deliver_one(configured_engine, now=now + 91, client=client)
    assert second["state"] == "sent" and second["attempts"] == 2
    assert len(sent) == 2
    assert "x" * 30 not in json.dumps(history(configured_engine))
    assert history(configured_engine)[0]["last_error"] is None


def test_expired_claim_is_recovered_and_permanent_error_is_inspectable(
    configured_engine, monkeypatch
):
    _, connector, _ = seed(configured_engine)
    message_id = enqueue_test(configured_engine, connector["id"])
    with configured_engine.begin() as connection:
        connection.execute(
            text("UPDATE outbox SET state='sending', lease_until=1, attempts=1 WHERE id=:id"),
            {"id": message_id},
        )
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    outcome = deliver_one(configured_engine, now=2000000000)
    assert outcome["state"] == "failed" and outcome["attempts"] == 2
    assert "environment" in history(configured_engine)[0]["last_error"]
    assert retry_failed(configured_engine, message_id) is True
    assert history(configured_engine)[0]["attempts"] == 0
    assert retry_failed(configured_engine, message_id) is False


def test_monitor_source_failure_isolation_and_persistent_schedule(configured_engine, monkeypatch):
    from vulnrelay import monitor

    seed(configured_engine)

    def failed(*args, **kwargs):
        raise httpx.ConnectError("source offline")

    calls = []
    monkeypatch.setattr(monitor, "refresh_epss", lambda *args: 0)
    monkeypatch.setattr(monitor, "sync_nvd", failed)
    monkeypatch.setattr(monitor, "sync_kev", lambda *args: calls.append("kev") or 12)
    monkeypatch.setattr(monitor, "deliver_one", lambda *args: None)
    from vulnrelay.config import get_settings

    first = cycle(configured_engine, get_settings(), now=100)
    assert first["sources"]["nvd"]["ok"] is False
    assert first["sources"]["cisa_kev"]["ok"] is True
    assert first["queued"] == 1
    second = cycle(configured_engine, get_settings(), now=101)
    assert second["sources"] == {}
    assert second["queued"] == 0
    assert calls == ["kev"]
    assert state(configured_engine)["last_cycle"] == 101
    with (
        monitor_lock(configured_engine),
        pytest.raises(RuntimeError),
        monitor_lock(configured_engine),
    ):
        pass


def test_render_telegram_utf16_limit():
    payload = {
        "vulnerability": {
            "id": "CVE-2026-1234",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "epss": None,
            "kev": None,
            "description": "💥" * 10000,
        },
        "rule": "Rule",
        "asset": "Asset",
        "format": "detailed",
        "match": {"confidence": "potential", "explanation": "Verify installed version"},
    }
    assert len(render(payload).encode("utf-16-le")) <= 7600
    assert "unknown" in render(payload)
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in render(payload)
    assert render(payload).endswith("(only available metrics shown).")


def test_configuration_validation_prevents_secret_storage(configured_engine):
    with pytest.raises(ValidationError):
        save_document(
            configured_engine, "connectors", {"name": "bad", "chat_id": "-123", "token": "secret"}
        )
    assert list_documents(configured_engine, "connectors") == []
    with pytest.raises(ValidationError):
        Rule(name="bad", destinations=["abc"], condition={"kind": "not", "children": []})


def test_delivery_pump_runs_during_source_work(configured_engine, monkeypatch):
    import threading

    from vulnrelay import monitor
    from vulnrelay.config import get_settings

    delivered = threading.Event()
    monkeypatch.setattr(monitor, "deliver_one", lambda *args: delivered.set())

    def slow_cycle(*args, **kwargs):
        assert delivered.wait(timeout=2), "Delivery pump was blocked by source work"
        raise KeyboardInterrupt

    monkeypatch.setattr(monitor, "cycle", slow_cycle)
    with pytest.raises(KeyboardInterrupt):
        monitor.run(configured_engine, get_settings())
