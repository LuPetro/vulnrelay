import pytest
from alembic import command
from alembic.config import Config

from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine


@pytest.fixture
def configured_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNRELAY_DATABASE_URL", f"sqlite:///{tmp_path / 'engine.db'}")
    monkeypatch.setenv("VULNRELAY_API_TOKEN", "")
    get_settings.cache_clear()
    command.upgrade(Config("backend/alembic.ini"), "head")
    engine = create_database_engine(get_settings().database_url)
    yield engine
    engine.dispose()
    get_settings.cache_clear()
