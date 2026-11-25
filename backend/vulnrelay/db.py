import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url


def create_database_engine(url: str) -> Engine:
    parsed = make_url(url)
    database_path = None
    created = False
    if parsed.get_backend_name() == "sqlite" and parsed.database not in (None, "", ":memory:"):
        database_path = Path(parsed.database).expanduser().resolve()
        database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        created = not database_path.exists()
    engine = create_engine(url, pool_pre_ping=True)
    if parsed.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def configure_sqlite(connection, _record):
            if created and database_path and database_path.exists():
                os.chmod(database_path, 0o600)
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine
