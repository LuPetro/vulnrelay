#!/usr/bin/env python3
"""Exercise API, packaged CLI, offline worker, persistence and backup in an isolated project."""

import json
import os
import subprocess
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

root = Path(__file__).resolve().parents[1]
project = "vulnrelay-smoke-" + uuid4().hex[:10]
environment = {**os.environ, "COMPOSE_PROJECT_NAME": project, "VULNRELAY_PORT": "18080"}
opener = build_opener(ProxyHandler({}))


def compose(*args):
    return subprocess.run(
        ["docker", "compose", *args], cwd=root, env=environment, check=True, timeout=180
    )


def request(path, method="GET", body=None):
    headers = {"Content-Type": "application/json", "X-VulnRelay-Request": "1"}
    token = os.environ.get("VULNRELAY_API_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    with opener.open(
        Request("http://127.0.0.1:18080" + path, data=data, headers=headers, method=method),
        timeout=10,
    ) as response:
        content = response.read()
        return (
            json.loads(content)
            if response.headers.get("content-type", "").startswith("application/json")
            else content
        )


try:
    compose("up", "-d", "--wait", "vulnrelay")
    assert request("/ready")["status"] == "ready"
    assert b'<div id="root"></div>' in request("/")
    # The pinned runtime image must provide real IANA data, including seasonal offsets.
    compose(
        "exec",
        "-T",
        "vulnrelay",
        "python",
        "-c",
        "from datetime import datetime,timedelta; from zoneinfo import ZoneInfo; "
        "zone=ZoneInfo('Europe/Vienna'); "
        "assert datetime(2026,1,1,tzinfo=zone).utcoffset()==timedelta(hours=1); "
        "assert datetime(2026,7,1,tzinfo=zone).utcoffset()==timedelta(hours=2); "
        "print('Packaged IANA timezone data verified.')",
    )
    # Prevent public source calls; this is an offline deployment test with no real destination.
    compose(
        "exec",
        "-T",
        "vulnrelay",
        "python",
        "-c",
        "import time; from vulnrelay.config import get_settings; from vulnrelay.db import create_database_engine; "
        "from vulnrelay.monitor import set_state; e=create_database_engine(get_settings().database_url); "
        "[set_state(e,'next_'+source,time.time()+86400) for source in ('nvd','cisa_kev','epss')]; e.dispose()",
    )
    compose("up", "-d", "--wait", "monitor")
    compose("exec", "-T", "monitor", "vulnrelay", "engine-health")
    asset = request(
        "/api/config/assets",
        "POST",
        {"name": "Synthetic smoke asset", "kind": "product", "product": "example"},
    )
    compose("restart", "monitor")
    compose("up", "-d", "--wait", "monitor")
    assert request("/api/config/assets")[0]["id"] == asset["id"]
    compose("exec", "-T", "vulnrelay", "vulnrelay", "backup", "/app/data/smoke-backup.db")
    compose("exec", "-T", "vulnrelay", "vulnrelay", "doctor")
    print("Isolated packaged API/UI/worker, restart persistence and backup smoke test passed.")
finally:
    subprocess.run(
        ["docker", "compose", "down", "--volumes", "--remove-orphans"],
        cwd=root,
        env=environment,
        check=False,
        timeout=180,
    )
