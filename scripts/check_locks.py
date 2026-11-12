#!/usr/bin/env python3
"""Reject missing/unpinned lock entries and drift from declared Python dependencies."""

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

root = Path(__file__).resolve().parents[1]
project = tomllib.loads((root / "backend/pyproject.toml").read_text())["project"]
locks = {}
for filename in ("requirements.lock", "requirements-dev.lock", "requirements-build.lock"):
    text = (root / "backend" / filename).read_text()
    entries = re.findall(r"^([a-zA-Z0-9_.-]+)==([^\s\\;]+)", text, re.MULTILINE)
    assert not re.search(r"https?://[^/\s]+@", text), "Credential-bearing index URL in lock"
    assert entries, f"{filename} has no pinned dependencies"
    assert "--hash=sha256:" in text, f"{filename} has no hashes"
    locks[filename] = {canonicalize_name(name): Version(version) for name, version in entries}
for declared in project["dependencies"]:
    requirement = Requirement(declared)
    if requirement.marker and not requirement.marker.evaluate():
        continue
    name = canonicalize_name(requirement.name)
    assert name in locks["requirements.lock"], f"Runtime dependency is missing: {name}"
    assert locks["requirements.lock"][name] in requirement.specifier, (
        f"Runtime lock is stale for {name}"
    )
for name, version in locks["requirements.lock"].items():
    assert locks["requirements-dev.lock"].get(name) == version, (
        f"Development lock differs for {name}"
    )
print("Python dependency lock declarations and versions verified.")
