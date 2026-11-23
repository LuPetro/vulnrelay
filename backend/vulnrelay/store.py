"""Small SQL document store shared by API and CLI."""

import json
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.schemas import Asset, Connector, Rule

MODELS = {"assets": Asset, "rules": Rule, "connectors": Connector}


def get_document(engine: Engine, table: str, document_id: str) -> dict | None:
    if table not in MODELS:
        raise ValueError("Unknown configuration collection")
    with engine.connect() as connection:
        row = connection.execute(
            text(f"SELECT id, document FROM {table} WHERE id=:id"), {"id": document_id}
        ).one_or_none()
        return {"id": row.id, **json.loads(row.document)} if row else None


def list_documents(engine: Engine, table: str) -> list[dict]:
    if table not in MODELS:
        raise ValueError("Unknown configuration collection")
    with engine.connect() as connection:
        return [
            {"id": row.id, **json.loads(row.document)}
            for row in connection.execute(text(f"SELECT id, document FROM {table} ORDER BY id"))
        ]


def save_document(
    engine: Engine, table: str, document: dict, document_id: str | None = None
) -> dict:
    if table not in MODELS:
        raise ValueError("Unknown configuration collection")
    validated = MODELS[table].model_validate(document)
    document_id = document_id or str(uuid4())
    if isinstance(validated, Rule):
        connectors = {row["id"] for row in list_documents(engine, "connectors")}
        assets = {row["id"] for row in list_documents(engine, "assets")}
        if set(validated.destinations) - connectors or set(validated.assets) - assets:
            raise ValueError("Rule refers to an unknown connector or asset")
    with engine.begin() as connection:
        if table == "assets":
            previous = connection.execute(
                text("SELECT document FROM assets WHERE id=:id"), {"id": document_id}
            ).scalar_one_or_none()
            if previous:
                old = json.loads(previous)
                current = validated.model_dump()
                fields = ("kind", "ecosystem", "package", "version")
                if (old.get("kind") == "package" or current.get("kind") == "package") and any(
                    old.get(field, "") != current.get(field, "") for field in fields
                ):
                    # The old version's successful check is not a check of the new one.
                    connection.execute(
                        text("DELETE FROM osv_findings WHERE asset_id=:id"), {"id": document_id}
                    )
                    connection.execute(
                        text("DELETE FROM osv_asset_state WHERE asset_id=:id"), {"id": document_id}
                    )
        connection.execute(
            text(f"""INSERT INTO {table} (id, document) VALUES (:id, :document)
            ON CONFLICT(id) DO UPDATE SET document=excluded.document"""),
            {"id": document_id, "document": validated.model_dump_json()},
        )
    return {"id": document_id, **validated.model_dump()}


def delete_document(engine: Engine, table: str, document_id: str) -> bool:
    if table not in MODELS:
        raise ValueError("Unknown configuration collection")
    with engine.begin() as connection:
        if table == "assets":
            connection.execute(
                text("DELETE FROM osv_findings WHERE asset_id=:id"), {"id": document_id}
            )
            connection.execute(
                text("DELETE FROM osv_asset_state WHERE asset_id=:id"), {"id": document_id}
            )
        return (
            connection.execute(
                text(f"DELETE FROM {table} WHERE id=:id"), {"id": document_id}
            ).rowcount
            > 0
        )
