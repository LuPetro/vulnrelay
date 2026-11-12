"""Operational checks and consistent SQLite backups without exposing credentials."""

import os
import sqlite3
import time
from importlib.resources import files
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine


def schema_head() -> str:
    config = Config()
    config.set_main_option("script_location", str(files("vulnrelay") / "migrations"))
    return ScriptDirectory.from_config(config).get_current_head()


def readiness(engine: Engine) -> dict:
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    if revision != schema_head():
        raise ValueError("Database migration is required")
    return {"status": "ready", "schema": revision}


def worker_health(engine: Engine, *, now: float | None = None) -> bool:
    import json

    with engine.connect() as connection:
        heartbeat = connection.execute(
            text("SELECT value FROM engine_state WHERE name='delivery_heartbeat'")
        ).scalar_one_or_none()
    current = time.time() if now is None else now
    return heartbeat is not None and 0 <= current - float(json.loads(heartbeat)) < 120


def backup_sqlite(engine: Engine, destination: Path) -> dict:
    """Use SQLite's online backup API so committed WAL data is included."""
    if (
        engine.dialect.name != "sqlite"
        or not engine.url.database
        or engine.url.database == ":memory:"
    ):
        raise ValueError("Online backup supports persistent SQLite databases only")
    destination = Path(destination).expanduser().resolve()
    if destination == Path(engine.url.database).resolve():
        raise ValueError("Backup destination cannot be the source database")
    # Exclusive creation prevents overwriting any user file; private mode protects inventory.
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        with engine.connect() as source, sqlite3.connect(destination) as backup:
            source.connection.driver_connection.backup(backup)
            if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Backup integrity verification failed")
        return {"backup": str(destination), "integrity": "ok", "bytes": destination.stat().st_size}
    except Exception:
        destination.unlink(missing_ok=True)
        raise
