import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from typer.testing import CliRunner
from vulnrelay.api import app
from vulnrelay.catalog import (
    _PRODUCTS,
    PACKS,
    PRODUCTS,
    CatalogSelection,
    catalog,
    import_selection,
)
from vulnrelay.cli import app as cli
from vulnrelay.config import get_settings
from vulnrelay.matching import match
from vulnrelay.schemas import Asset
from vulnrelay.store import get_document, list_documents, save_document

HEADERS = {"x-vulnrelay-request": "1"}


def test_catalog_identity_and_pack_integrity():
    assert len(PRODUCTS) >= 87
    assert len(_PRODUCTS) == len(PRODUCTS)  # Stable IDs must not silently overwrite another entry.
    assert len(PACKS) >= 19
    assert len({(p["vendor"], p["product"]) for p in PRODUCTS.values()}) == len(PRODUCTS)
    assert len({p["id"] for p in PACKS}) == len(PACKS)
    for pack in PACKS:
        assert set(pack["products"]) <= PRODUCTS.keys()
        assert len(pack["products"]) == len(set(pack["products"]))
    for item in PRODUCTS.values():
        asset = Asset(
            name=item["name"], kind=item["kind"], vendor=item["vendor"], product=item["product"]
        )
        cpe = f"cpe:2.3:a:{item['vendor'] or 'example'}:{item['product']}:1.0:*:*:*:*:*:*:*"
        evidence = match(
            asset,
            {"nvd": {"configurations": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}},
        )
        assert evidence["confidence"] == "potential"
    assert catalog("POSTGRES")["products"][0]["id"] == "postgresql"
    assert catalog("K8S")["products"][0]["id"] == "kubernetes"
    assert catalog("not-present")["products"] == []


def test_preview_then_repeated_and_overlapping_imports(configured_engine):
    selection = CatalogSelection(products=["nginx", "postgresql", "nginx"], group=" web ")
    preview = import_selection(configured_engine, selection, preview=True)
    assert len(preview["created"]) == 2 and preview["preview"] is True
    assert list_documents(configured_engine, "assets") == []
    first = import_selection(configured_engine, selection)
    second = import_selection(configured_engine, selection)
    assert second["created"] == [] and second["existing"] == first["created"]
    overlap = import_selection(
        configured_engine, CatalogSelection(products=["postgresql", "redis"], group="web")
    )
    assert len(overlap["existing"]) == 1 and len(overlap["created"]) == 1
    with configured_engine.connect() as c:
        assert c.execute(text("SELECT COUNT(*) FROM outbox")).scalar() == 0
        assert c.execute(text("SELECT COUNT(*) FROM rules")).scalar() == 0


def test_manual_assets_reused_without_overwrite_and_contexts_remain_distinct(configured_engine):
    existing = save_document(
        configured_engine,
        "assets",
        {
            "name": "My edited database",
            "kind": "vendor_product",
            "vendor": "PostgreSQL",
            "product": "PostgreSQL",
            "group": "production",
            "environment": "production",
            "enabled": False,
            "importance": "critical",
            "exposed": True,
            "tags": ["keep-me"],
        },
    )
    selection = CatalogSelection(products=["postgresql"])
    result = import_selection(configured_engine, selection)
    assert result["created"] == [] and result["existing"][0] == existing
    assert get_document(configured_engine, "assets", existing["id"]) == existing
    for field, value in (("group", "other"), ("environment", "staging"), ("team", "ops")):
        assert (
            len(
                import_selection(configured_engine, selection.model_copy(update={field: value}))[
                    "created"
                ]
            )
            == 1
        )
    assert len(list_documents(configured_engine, "assets")) == 4


def test_concurrent_imports_do_not_duplicate(configured_engine):
    selection = CatalogSelection(products=["ubuntu", "openssh", "nginx"])
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: import_selection(configured_engine, selection), range(4)))
    assert sum(len(r["created"]) for r in results) == 3
    assert len(list_documents(configured_engine, "assets")) == 3


@pytest.mark.parametrize(
    "document",
    [
        {"products": ["nginx", "made-up"]},
        {"products": []},
        {"products": ["nginx"], "group": "  "},
        {"products": ["nginx"], "importance": "invalid"},
        {"products": ["nginx"], "token": "do-not-echo-me"},
    ],
)
def test_invalid_selection_is_atomic_and_safe(configured_engine, document):
    with TestClient(app, base_url="http://localhost", headers=HEADERS) as client:
        response = client.post("/api/catalog/import", json=document)
        assert response.status_code == 422
        assert "do-not-echo-me" not in response.text
    assert list_documents(configured_engine, "assets") == []


def test_failed_insert_rolls_back_whole_pack(configured_engine):
    with configured_engine.begin() as c:
        c.exec_driver_sql("""CREATE TRIGGER fail_second BEFORE INSERT ON assets
        WHEN json_extract(NEW.document, '$.product') = 'openssh'
        BEGIN SELECT RAISE(ABORT, 'test failure'); END""")
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        import_selection(configured_engine, CatalogSelection(products=["ubuntu", "openssh"]))
    assert list_documents(configured_engine, "assets") == []


def test_catalog_api_guards_and_preview(configured_engine, monkeypatch):
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/catalog?q=nginx").json()["products"][0]["id"] == "nginx"
        assert client.post("/api/catalog/import", json={"products": ["nginx"]}).status_code == 403
        assert (
            client.post(
                "/api/catalog/import",
                json={"products": ["nginx"]},
                headers={**HEADERS, "origin": "https://attacker.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/catalog/preview", json={"products": ["nginx"]}, headers=HEADERS
            ).json()["preview"]
            is True
        )
        assert list_documents(configured_engine, "assets") == []
    monkeypatch.setenv("VULNRELAY_API_TOKEN", "catalog-test")
    get_settings.cache_clear()
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/catalog").status_code == 401
        assert (
            client.post(
                "/api/catalog/import", json={"products": ["nginx"]}, headers=HEADERS
            ).status_code
            == 401
        )


def test_catalog_cli_preview_import_and_reimport(configured_engine, tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["catalog", "pack", "linux-server", "--preview"])
    assert result.exit_code == 0 and len(json.loads(result.stdout)["created"]) == 4
    assert list_documents(configured_engine, "assets") == []
    assert runner.invoke(cli, ["catalog", "pack", "linux-server"]).exit_code == 0
    assert (
        json.loads(runner.invoke(cli, ["catalog", "pack", "linux-server"]).stdout)["created"] == []
    )
    assert runner.invoke(cli, ["catalog", "pack", "not-a-pack"]).exit_code == 1
    selection = tmp_path / "selection.json"
    selection.write_text(json.dumps({"products": ["nginx"], "environment": "homelab"}))
    assert runner.invoke(cli, ["catalog", "add", str(selection)]).exit_code == 0
    assert (
        json.loads(runner.invoke(cli, ["catalog", "list", "--query", "ssh"]).stdout)["products"][0][
            "id"
        ]
        == "openssh"
    )


@pytest.mark.parametrize(
    "query,product",
    [
        ("npm lodash", "lodash"),
        ("PyPI fastapi", "fastapi"),
        ("Composer laravel", "laravel"),
        ("MikroTik RouterOS", "routeros"),
        ("Backup Proxmox", "proxmox-backup"),
        ("Identity authentik", "authentik"),
    ],
)
def test_expanded_catalog_is_searchable_by_product_ecosystem_and_category(query, product):
    assert product in {item["id"] for item in catalog(query)["products"]}
    assert PRODUCTS[product]["source_url"].startswith("https://nvd.nist.gov/")


def test_new_packs_import_atomically_and_share_existing_identity_context(configured_engine):
    pack_ids = {"python-api", "javascript-app", "files-backups", "open-network"}
    chosen = [pack for pack in PACKS if pack["id"] in pack_ids]
    assert len(chosen) == len(pack_ids)
    products = [product for pack in chosen for product in pack["products"]]
    selection = CatalogSelection(products=products, group="new-stack", environment="homelab")
    preview = import_selection(configured_engine, selection, preview=True)
    assert len(preview["created"]) == len(set(products))
    assert list_documents(configured_engine, "assets") == []
    first = import_selection(configured_engine, selection)
    second = import_selection(configured_engine, selection)
    assert len(first["created"]) == len(set(products))
    assert second["created"] == []
    assert {item["id"] for item in second["existing"]} == {item["id"] for item in first["created"]}
    # A library is an explicit product watch, not a keyword or package/version claim.
    requests = next(item for item in first["created"] if item["product"] == "requests")
    assert requests["kind"] == "vendor_product" and requests["vendor"] == "python"
    assert requests["version"] == ""
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM outbox")).scalar() == 0


@pytest.mark.parametrize(
    "product,criteria",
    [
        ("mariadb", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"),
        ("routeros", "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*"),
        ("vaultwarden", "cpe:2.3:a:dani-garcia:vaultwarden:*:*:*:*:*:*:*:*"),
        ("rabbitmq", "cpe:2.3:a:broadcom:rabbitmq_server:3.8.34:*:*:*:*:*:*:*"),
        ("requests", "cpe:2.3:a:python:requests:1.2.0:*:*:*:*:*:*:*"),
    ],
)
def test_reviewed_catalog_identities_match_conservatively(product, criteria):
    # Representative identities from the linked NVD records in docs/catalog-sources.md.
    # This is intentionally product-level: CPE ranges and installed packages are not verified.
    item = PRODUCTS[product]
    asset = Asset(
        name=item["name"], kind=item["kind"], vendor=item["vendor"], product=item["product"]
    )
    record = {
        "nvd": {"configurations": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria}]}]}
    }
    evidence = match(asset, record)
    assert evidence["confidence"] == "potential"
    other_vendor = asset.model_copy(update={"vendor": "unrelated_vendor"})
    assert match(other_vendor, record) is None
    other_product = asset.model_copy(update={"product": item["product"] + "_plugin"})
    assert match(other_product, record) is None
