#!/usr/bin/env python3
"""Check the repository's deliberately read-only CI policy before publication."""

import re
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
for path in sorted((root / ".github/workflows").glob("*.yml")):
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert workflow.get("permissions") == {"contents": "read"}, (
        f"{path.name}: expected read-only token"
    )
    assert "pull_request_target" not in workflow["on"], (
        f"{path.name}: privileged fork trigger is forbidden"
    )
    assert workflow.get("concurrency"), f"{path.name}: concurrency policy missing"
    for name, job in workflow["jobs"].items():
        assert 1 <= int(job["timeout-minutes"]) <= 30, f"{path.name}/{name}: invalid timeout"
        assert not job.get("permissions"), (
            f"{path.name}/{name}: job token permissions require explicit policy review"
        )
        for step in job["steps"]:
            action = step.get("uses")
            if action:
                assert re.search(r"@[0-9a-f]{40}$", action), (
                    f"{path.name}: action is not commit-pinned"
                )
    print(f"Workflow policy verified: {path.name}")
