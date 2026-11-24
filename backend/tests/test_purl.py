import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_osv import advisory
from typer.testing import CliRunner
from vulnrelay import cli, osv
from vulnrelay.api import app
from vulnrelay.matching import match
from vulnrelay.pipeline import vulnerabilities
from vulnrelay.schemas import Asset
from vulnrelay.store import save_document


@pytest.mark.parametrize(
    ("purl", "ecosystem", "package", "version"),
    [
        ("pkg:npm/next@15.1.0", "npm", "next", "15.1.0"),
        ("pkg:npm/%40angular/core@17.1.0", "npm", "@angular/core", "17.1.0"),
        ("pkg:pypi/django@5.1.0", "PyPI", "django", "5.1.0"),
        ("pkg:golang/github.com/gorilla/mux@v1.8.1", "Go", "github.com/gorilla/mux", "v1.8.1"),
        (
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
            "Maven",
            "org.apache.commons:commons-lang3",
            "3.12.0",
        ),
        ("pkg:cargo/serde@1.0.0", "crates.io", "serde", "1.0.0"),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", "NuGet", "Newtonsoft.Json", "13.0.1"),
        ("pkg:pypi/example@1.0%2Blocal", "PyPI", "example", "1.0+local"),
    ],
)
def test_purl_converts_to_existing_package_identity(purl, ecosystem, package, version):
    asset = Asset.model_validate({"name": "Dependency", "kind": "package", "purl": purl})
    assert (asset.ecosystem, asset.package, asset.version) == (ecosystem, package, version)
    assert "purl" not in asset.model_dump()


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:npm/next",
        "pkg:npm/next@1.x",
        "pkg:npm/next@*",
        "pkg:npm/next@latest",
        "pkg:npm/next@1.0.0?repository_url=evil",
        "pkg:npm/next@1.0.0#subdirectory",
        "pkg:npm/%40scope%2Fother/name@1.0.0",
        "pkg:npm/@scope/name@1.0.0",
        "pkg:npm/%ZZ/name@1.0.0",
        "pkg:npm/%FF/name@1.0.0",
        "pkg:maven/only-name@1.0.0",
        "pkg:golang/only-name@1.0.0",
        "pkg:pypi/namespace/name@1.0.0",
        "pkg:deb/debian/curl@1.0.0",
        "pkg:npm/next@1.0.0@2.0.0",
    ],
)
def test_purl_rejects_ambiguous_or_unsupported_identifiers(purl):
    with pytest.raises(ValidationError):
        Asset.model_validate({"name": "Dependency", "kind": "package", "purl": purl})


def test_purl_conflicts_and_other_asset_kinds_are_rejected():
    with pytest.raises(ValidationError):
        Asset.model_validate(
            {
                "name": "Dependency",
                "kind": "package",
                "purl": "pkg:npm/next@15.1.0",
                "version": "16.0.0",
            }
        )
    with pytest.raises(ValidationError):
        Asset.model_validate(
            {"name": "Dependency", "kind": "product", "purl": "pkg:npm/next@15.1.0"}
        )


def test_purl_api_preview_and_create_do_not_echo_invalid_input(configured_engine):
    with TestClient(app, base_url="http://localhost") as client:
        assert (
            client.post("/api/assets/parse-purl", json={"purl": "pkg:npm/next@15.1.0"}).status_code
            == 403
        )
        headers = {"x-vulnrelay-request": "1"}
        result = client.post(
            "/api/assets/parse-purl", json={"purl": "pkg:npm/%40scope/name@1.2.3"}, headers=headers
        )
        assert result.status_code == 200
        assert result.json() == {"ecosystem": "npm", "package": "@scope/name", "version": "1.2.3"}
        bad_value = "not-an-identifier-with-private-information"
        bad = client.post("/api/assets/parse-purl", json={"purl": bad_value}, headers=headers)
        assert bad.status_code == 422 and bad_value not in bad.text
        saved = client.post(
            "/api/config/assets",
            json={"name": "Dependency", "kind": "package", "purl": "pkg:pypi/django@5.1.0"},
            headers=headers,
        )
        assert saved.status_code == 201
        assert saved.json()["package"] == "django" and "purl" not in saved.json()


def test_purl_can_be_imported_headlessly_from_json(configured_engine, tmp_path):
    path = tmp_path / "dependency.json"
    path.write_text(
        json.dumps({"name": "Dependency", "kind": "package", "purl": "pkg:cargo/serde@1.0.0"})
    )
    result = CliRunner().invoke(cli.app, ["assets", "add", str(path)])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["ecosystem"] == "crates.io"


def test_purl_asset_osv_matching_and_version_change(configured_engine):
    original = save_document(
        configured_engine,
        "assets",
        {"name": "Dependency", "kind": "package", "purl": "pkg:npm/next@15.1.0"},
    )
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request) or httpx.Response(200, json={"vulns": [advisory()]})
            )
        )
    ) as client:
        assert osv.refresh(configured_engine, client=client)["cve_findings"] == 1
    assert json.loads(requests[0].content) == {
        "package": {"name": "next", "ecosystem": "npm"},
        "version": "15.1.0",
    }
    record = next(vulnerabilities(configured_engine, "CVE-2026-1234"))
    assert (
        match(Asset.model_validate({k: v for k, v in original.items() if k != "id"}), record)[
            "confidence"
        ]
        == "confirmed"
    )
    updated = save_document(
        configured_engine,
        "assets",
        {"name": "Dependency", "kind": "package", "purl": "pkg:npm/next@16.0.0"},
        original["id"],
    )
    assert updated["version"] == "16.0.0" and osv.asset_status(configured_engine) == []
    record = next(vulnerabilities(configured_engine, "CVE-2026-1234"), None)
    assert (
        record is None
        or match(Asset.model_validate({k: v for k, v in updated.items() if k != "id"}), record)
        is None
    )
