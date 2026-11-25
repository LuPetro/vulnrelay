#!/usr/bin/env python3
"""Install a built wheel into a fresh venv and initialize a database outside the checkout."""

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
wheel = Path(sys.argv[1]).resolve()
assert wheel.is_file() and wheel.suffix == ".whl"
with zipfile.ZipFile(wheel) as archive:
    notice_paths = [
        name for name in archive.namelist() if name.endswith(".dist-info/licenses/NOTICE")
    ]
    assert len(notice_paths) == 1, "Wheel must contain exactly one attribution notice"
    assert archive.read(notice_paths[0]) == (root / "NOTICE").read_bytes(), (
        "Wheel attribution notice differs"
    )
with tempfile.TemporaryDirectory(prefix="vulnrelay-wheel-") as temporary:
    work = Path(temporary)
    venv = work / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    binary = venv / ("Scripts" if os.name == "nt" else "bin")
    python = binary / "python"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--python",
            str(python),
            "install",
            "--require-hashes",
            "-r",
            str(root / "backend/requirements.lock"),
        ],
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "pip", "--python", str(python), "install", "--no-deps", str(wheel)],
        check=True,
    )
    environment = {
        **os.environ,
        "VULNRELAY_DATABASE_URL": f"sqlite:///{work / 'test.db'}",
        "VULNRELAY_API_TOKEN": "",
    }
    for args in (["init"], ["doctor"], ["config", "validate"]):
        subprocess.run([str(binary / "vulnrelay"), *args], cwd=work, env=environment, check=True)
print("Built wheel works outside the source checkout.")
