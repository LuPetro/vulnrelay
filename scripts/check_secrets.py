#!/usr/bin/env python3
"""Scan tracked source without network verification or printing detected secret values."""

import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
files = [name for name in files if name and (root / name).is_file()]
for name in files:
    path = Path(name)
    if path.name.startswith(".env") and path.name != ".env.example":
        raise SystemExit(f"Refusing a tracked environment file: {name}")
    if path.suffix in {".db", ".sqlite", ".sqlite3", ".pem", ".key"}:
        raise SystemExit(f"Refusing a tracked database/private-key candidate: {name}")
# Baseline exceptions are hashes of reviewed non-secrets. Verification is explicitly offline.
result = subprocess.run(
    [
        sys.executable,
        "-m",
        "detect_secrets.pre_commit_hook",
        "--no-verify",
        "-c",
        "1",
        "--baseline",
        ".secrets.baseline",
        *files,
    ],
    cwd=root,
    capture_output=True,
    text=True,
)
if result.returncode:
    # The underlying tool may include source lines; report only the failure, not values.
    print(
        "Secret scan failed. Run detect-secrets-hook locally with --no-verify to inspect and review findings.",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(f"Offline tracked-source secret scan passed ({len(files)} files).")
