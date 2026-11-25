#!/usr/bin/env python3
"""Validate release metadata without publishing anything."""

import argparse
import json
import tomllib
from pathlib import Path

from packaging.version import Version

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--tag", help="Optional intended release tag, e.g. v0.1.0-alpha.0")
args = parser.parse_args()
backend = tomllib.loads((root / "backend/pyproject.toml").read_text())["project"]
frontend = json.loads((root / "frontend/package.json").read_text())
assert Version(backend["version"]) == Version(frontend["version"]), (
    "Frontend/backend versions differ"
)
assert backend["license"] == "Apache-2.0", "Unexpected package license"
assert (root / "LICENSE").read_bytes() == (root / "backend/LICENSE").read_bytes(), (
    "Packaged license differs"
)
assert frontend["license"] == backend["license"], "Frontend license differs"
assert (root / "LICENSE").read_bytes() == (root / "frontend/public/LICENSE").read_bytes(), (
    "Static Apache license differs"
)
assert (root / "NOTICE").read_bytes() == (root / "backend/NOTICE").read_bytes(), (
    "Packaged attribution notice differs"
)
assert (root / "NOTICE").read_bytes() == (root / "frontend/public/NOTICE").read_bytes(), (
    "Static attribution notice differs"
)
assert set(backend["license-files"]) == {"LICENSE", "NOTICE"}, "Package license files differ"
assert frontend["private"] is True, "Frontend is a private static application, not an npm package"
assert (root / "THIRD_PARTY_NOTICES.md").read_bytes() == (
    root / "frontend/public/THIRD_PARTY_NOTICES.md"
).read_bytes(), "Static third-party notice differs"
if args.tag:
    assert Version(args.tag.removeprefix("v")) == Version(backend["version"]), (
        "Release tag differs from package version"
    )
print(f"Release metadata verified: {backend['version']} / {frontend['version']}")
