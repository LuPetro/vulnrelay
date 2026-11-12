#!/usr/bin/env python3
"""Isolated real API/UI server for browser tests; never starts monitoring or real delivery."""

import json
import os
import tempfile
from importlib.resources import files
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="vulnrelay-browser-") as directory:
    os.environ["VULNRELAY_DATABASE_URL"] = f"sqlite:///{Path(directory) / 'browser.db'}"
    os.environ["VULNRELAY_API_TOKEN"] = ""
    os.environ["VULNRELAY_UI_DIR"] = str(root / "frontend/dist")
    os.environ["TELEGRAM_BOT_TOKEN"] = ""  # Deliberately forbid outbound Telegram calls in tests.

    import uvicorn
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from vulnrelay.config import get_settings
    from vulnrelay.db import create_database_engine

    get_settings.cache_clear()
    config = Config()
    config.set_main_option("script_location", str(files("vulnrelay") / "migrations"))
    command.upgrade(config, "head")
    engine = create_database_engine(get_settings().database_url)
    record = {
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*",
                            }
                        ],
                    }
                ]
            }
        ]
    }
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulnerabilities
            (id,modified,status,description,cvss_score,severity,nvd_raw)
            VALUES ('CVE-2026-1234','2026-11-12','Analyzed','Synthetic browser test fixture: Example Server',9.8,'CRITICAL',:raw)"""),
            {"raw": json.dumps(record)},
        )
    engine.dispose()
    uvicorn.run("vulnrelay.api:app", host="127.0.0.1", port=8765, log_level="warning")
