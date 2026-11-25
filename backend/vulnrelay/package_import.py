"""Preview and atomically import exact-version package URL selections."""

from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.osv import identity as osv_identity
from vulnrelay.schemas import Asset


class PackageSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purls: list[Annotated[str, Field(min_length=1, max_length=1000)]] = Field(
        min_length=1, max_length=100
    )
    group: str = Field(default="application", min_length=1, max_length=100)
    environment: str = Field(default="", max_length=100)
    team: str = Field(default="", max_length=100)
    importance: Literal["low", "normal", "high", "critical"] = "normal"
    exposed: bool = False

    @field_validator("group", "environment", "team")
    @classmethod
    def clean_context(cls, value, info):
        value = value.strip()
        if info.field_name == "group" and not value:
            raise ValueError("An asset group is required")
        return value


class InvalidPackageURL(ValueError):
    def __init__(self, index: int):
        self.index = index
        super().__init__("Invalid package URL")


def _identity(asset: Asset) -> tuple:
    return (*osv_identity(asset), asset.group, asset.environment, asset.team)


def import_packages(engine: Engine, selection: PackageSelection, *, preview: bool = False) -> dict:
    """Validate everything before writing and serialize duplicate checks and inserts."""
    candidates = []
    context = selection.model_dump(exclude={"purls"})
    for index, purl in enumerate(selection.purls, start=1):
        try:
            asset = Asset.model_validate(
                {"name": "Package", "kind": "package", "purl": purl, **context}
            )
        except ValueError:
            raise InvalidPackageURL(index) from None
        asset.name = f"{asset.ecosystem} {asset.package}"[:120]
        candidates.append(asset)
    result: dict = {"created": [], "existing": [], "preview": preview}
    with engine.connect() as connection:
        if not preview:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            elif engine.dialect.name == "postgresql":
                connection.exec_driver_sql("LOCK TABLE assets IN SHARE ROW EXCLUSIVE MODE")
            else:
                raise ValueError("Unsupported database for package imports")
        existing = {}
        for row in connection.execute(text("SELECT id,document FROM assets ORDER BY id")):
            try:
                asset = Asset.model_validate_json(row.document)
            except ValueError:
                continue
            if asset.kind == "package":
                existing.setdefault(_identity(asset), {"id": row.id, **asset.model_dump()})
        for asset in candidates:
            key = _identity(asset)
            if key in existing:
                result["existing"].append(existing[key])
                continue
            document = {"id": str(uuid4()), **asset.model_dump()}
            result["created"].append(document)
            existing[key] = document
            if not preview:
                connection.execute(
                    text("INSERT INTO assets (id,document) VALUES (:id,:document)"),
                    {"id": document["id"], "document": asset.model_dump_json()},
                )
        if not preview:
            connection.commit()
    return result
