import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from typer.testing import CliRunner
from vulnrelay import cli
from vulnrelay.api import app
from vulnrelay.package_import import PackageSelection, import_packages
from vulnrelay.store import get_document, list_documents, save_document

HEADERS = {"x-vulnrelay-request": "1"}


def selection(**changes):
    return PackageSelection.model_validate(
        {
            "purls": ["pkg:npm/next@15.1.0", "pkg:pypi/django@5.1.0", "pkg:pypi/Django@5.1.0"],
            "group": "app",
            **changes,
        }
    )


def test_preview_repeat_and_overlap_do_not_create_duplicates(configured_engine):
    preview = import_packages(configured_engine, selection(), preview=True)
    assert len(preview["created"]) == 2 and len(preview["existing"]) == 1
    assert preview["preview"] is True and list_documents(configured_engine, "assets") == []
    first = import_packages(configured_engine, selection())
    assert len(first["created"]) == 2 and len(first["existing"]) == 1
    repeated = import_packages(configured_engine, selection())
    assert repeated["created"] == [] and len(repeated["existing"]) == 3
    with configured_engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM outbox")).scalar() == 0
        assert connection.execute(text("SELECT COUNT(*) FROM rules")).scalar() == 0


def test_existing_settings_are_preserved_and_context_and_versions_remain_distinct(
    configured_engine,
):
    existing = save_document(
        configured_engine,
        "assets",
        {
            "name": "My dependency",
            "kind": "package",
            "ecosystem": "PyPI",
            "package": "my_package",
            "version": "1.0",
            "group": "app",
            "enabled": False,
            "importance": "critical",
            "exposed": True,
            "tags": ["retain"],
        },
    )
    same = selection(purls=["pkg:pypi/my-package@1.0"])
    assert import_packages(configured_engine, same)["existing"] == [existing]
    assert get_document(configured_engine, "assets", existing["id"]) == existing
    for change in (
        {"group": "other"},
        {"environment": "staging"},
        {"team": "ops"},
        {"purls": ["pkg:pypi/my-package@1.0.0"]},
    ):
        assert (
            len(import_packages(configured_engine, same.model_copy(update=change))["created"]) == 1
        )


def test_concurrent_imports_serialize_duplicate_checks(configured_engine):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: import_packages(configured_engine, selection()), range(4))
        )
    assert sum(len(result["created"]) for result in results) == 2
    assert len(list_documents(configured_engine, "assets")) == 2


def test_failed_insert_rolls_back_entire_selection(configured_engine):
    with configured_engine.begin() as connection:
        connection.exec_driver_sql("""CREATE TRIGGER fail_django BEFORE INSERT ON assets
        WHEN json_extract(NEW.document, '$.package') = 'django'
        BEGIN SELECT RAISE(ABORT, 'test failure'); END""")
    with pytest.raises(IntegrityError):
        import_packages(configured_engine, selection())
    assert list_documents(configured_engine, "assets") == []


def test_api_validates_entire_selection_without_reflecting_input(configured_engine):
    document = {"purls": ["pkg:npm/next@15.1.0", "bad-private-information"]}
    with TestClient(app, base_url="http://localhost") as client:
        assert client.post("/api/packages/preview", json=document).status_code == 403
        response = client.post("/api/packages/import", json=document, headers=HEADERS)
        assert response.status_code == 422 and "Package URL 2" in response.text
        assert "bad-private-information" not in response.text
        assert (
            client.post("/api/packages/import", json={"purls": []}, headers=HEADERS).status_code
            == 422
        )
        assert (
            client.post(
                "/api/packages/import",
                json={"purls": ["pkg:npm/next@1.0.0"] * 101},
                headers=HEADERS,
            ).status_code
            == 422
        )
        result = client.post(
            "/api/packages/preview", json=selection().model_dump(), headers=HEADERS
        )
        assert result.status_code == 200 and len(result.json()["created"]) == 2
    assert list_documents(configured_engine, "assets") == []


def test_cli_preview_then_import(configured_engine, tmp_path):
    path = tmp_path / "packages.json"
    path.write_text(selection().model_dump_json())
    runner = CliRunner()
    preview = runner.invoke(cli.app, ["packages", "import", str(path), "--preview"])
    assert preview.exit_code == 0 and len(json.loads(preview.stdout)["created"]) == 2
    assert list_documents(configured_engine, "assets") == []
    result = runner.invoke(cli.app, ["packages", "import", str(path)])
    assert result.exit_code == 0 and len(json.loads(result.stdout)["created"]) == 2
    assert len(list_documents(configured_engine, "assets")) == 2
