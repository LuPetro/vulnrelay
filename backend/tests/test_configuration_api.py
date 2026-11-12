from fastapi.testclient import TestClient
from vulnrelay.api import app
from vulnrelay.config import get_settings

HEADERS = {"x-vulnrelay-request": "1"}


def test_first_run_and_configuration_round_trip(configured_engine):
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/overview").json()["setup_required"] is True
        assert client.post("/api/config/assets", json={"name": "x"}).status_code == 403
        assert (
            client.post(
                "/api/config/assets",
                json={},
                headers={**HEADERS, "origin": "https://attacker.invalid"},
            ).status_code
            == 403
        )
        response = client.post(
            "/api/config/assets",
            json={"name": "NGINX", "kind": "product", "product": "nginx"},
            headers=HEADERS,
        )
        assert response.status_code == 201
        asset_id = response.json()["id"]
        assert client.get("/api/config/assets").json()[0]["product"] == "nginx"
        bad = client.post(
            "/api/config/connectors",
            json={"name": "Secret", "chat_id": "-123", "token": "never-echo-this"},
            headers=HEADERS,
        )
        assert bad.status_code == 422
        assert "never-echo-this" not in bad.text
        assert client.delete(f"/api/config/assets/{asset_id}", headers=HEADERS).status_code == 200
        assert client.get("/api/config/assets").json() == []
        assert client.get("/api/overview", headers={"host": "attacker.invalid"}).status_code == 400


def test_optional_api_token_is_required(configured_engine, monkeypatch):
    monkeypatch.setenv("VULNRELAY_API_TOKEN", "a-private-token")
    get_settings.cache_clear()
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/overview").status_code == 401
        assert (
            client.get("/api/overview", headers={"authorization": "Bearer wrong"}).status_code
            == 401
        )
        assert (
            client.get(
                "/api/overview", headers={"authorization": "Bearer a-private-token"}
            ).status_code
            == 200
        )
        assert client.get("/health").status_code == 200


def test_api_to_queue_to_telegram_end_to_end(configured_engine, monkeypatch):
    import json

    import httpx
    from sqlalchemy import text
    from vulnrelay import delivery

    token = "123456:" + "z" * 30
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", token)
    cpe = "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"
    raw = {"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}]}
    with configured_engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities (id,modified,status,cvss_score,severity,nvd_raw)
            VALUES ('CVE-2026-1234','2026-11-12','Analyzed',9.8,'CRITICAL',:raw)"""),
            {"raw": json.dumps(raw)},
        )
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    original = delivery.send_telegram
    with httpx.Client(transport=httpx.MockTransport(handler)) as telegram:
        monkeypatch.setattr(
            delivery,
            "send_telegram",
            lambda config, message, **kwargs: original(config, message, client=telegram),
        )
        with TestClient(app, base_url="http://localhost", headers=HEADERS) as client:
            asset = client.post(
                "/api/config/assets", json={"name": "Production", "kind": "cpe", "cpe": cpe}
            ).json()
            connector = client.post(
                "/api/config/connectors", json={"name": "Telegram", "chat_id": "-123456"}
            ).json()
            rule = client.post(
                "/api/config/rules",
                json={
                    "name": "Critical",
                    "assets": [asset["id"]],
                    "destinations": [connector["id"]],
                    "condition": {
                        "kind": "all",
                        "children": [
                            {"kind": "condition", "field": "cvss", "op": "gte", "value": 9},
                            {"kind": "condition", "field": "vendor", "op": "eq", "value": "vendor"},
                        ],
                    },
                },
            )
            assert rule.status_code == 201
            assert client.get("/api/overview").json()["setup_required"] is False
            preview = client.get("/api/evaluate").json()
            assert preview["reports"][0]["match"]["confidence"] == "confirmed"
            assert client.post("/api/queue/evaluate").json()["queued"] == 1
            assert client.post("/api/queue/evaluate").json()["queued"] == 0
            result = client.post("/api/deliveries/next")
            assert result.status_code == 200 and result.json()["state"] == "sent"
            history = client.get("/api/deliveries")
            assert history.json()[0]["state"] == "sent"
            assert token not in history.text
    assert len(sent) == 1
    assert "CVE-2026-1234" in sent[0]["text"]
    assert "Why:" in sent[0]["text"]
