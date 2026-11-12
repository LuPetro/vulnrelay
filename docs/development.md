# Development and verification

Use Python 3.12 or 3.13, Node 22.12+ LTS and a recent Docker Compose. Runtime dependencies, build tools and developer tools have separate hash-locked requirement files. Frontend dependencies use npm's integrity-checked package lock. Docker base images and GitHub Actions use immutable digests/commit SHAs.

## Setup and checks

Create/activate a venv, then `make install`. The editable package installation uses the already-locked build tools and does not resolve extra runtime dependencies. `make lint`, `make test`, `make frontend` and `make audit` reproduce the main checks. Ruff uses backend/pyproject.toml explicitly for both Python source and scripts; Prettier and TypeScript check the frontend. Coverage includes branches with a 75% minimum to detect regression, not as a substitute for meaningful assertions. Tests cover provider failures, uncertainty, delivery/restart behavior and operational safeguards.

After `docker compose build`, `python3 scripts/container_smoke.py` starts a separate disposable Compose project on localhost:18080, prevents public-source sync, checks API/UI/worker health and restart persistence, verifies a backup and removes only its own test volume. Do not run simultaneous smoke tests on the same host port.

For real-browser tests, build the frontend, install Chromium with `cd frontend && npx playwright install --with-deps chromium`, then run `npm run test:e2e`. The Python package must be installed in the active environment; `PYTHON_BIN` may select its interpreter. Playwright starts a temporary API/database on 127.0.0.1:8765 with synthetic CVE data, an explicitly empty Telegram token and no monitoring worker. It tests configuration, rule evidence, queue failure/retry and a mobile viewport without contacting Telegram or intelligence sources. `PLAYWRIGHT_EXTERNAL_SERVER=1` is only for a manually started copy of scripts/e2e_server.py, never a real user instance. Failure traces/screenshots contain only the synthetic test inventory.

## Dependency updates

Review `backend/pyproject.toml` first. Use the pinned pip-tools from the developer lock:

```sh
pip-compile --generate-hashes --strip-extras --allow-unsafe --no-emit-index-url -o backend/requirements.lock backend/pyproject.toml
pip-compile --generate-hashes --strip-extras --allow-unsafe --no-emit-index-url -o backend/requirements-build.lock backend/requirements-build.in
pip-compile --extra dev --extra quality -c backend/requirements.lock --generate-hashes --strip-extras --allow-unsafe --no-emit-index-url -o backend/requirements-dev.lock backend/pyproject.toml
python scripts/check_locks.py
```

These commands preserve existing pins unless an update is requested; add `--upgrade` for an intentional refresh. Commit declarations and locks together. CI checks declared runtime constraints and common runtime/development versions, installs with hash verification and audits known vulnerabilities. Review platform/Python compatibility before accepting upgrades. PostgreSQL is an unvalidated optional extra (`pip install 'backend[postgres]'`); its extra dependencies are not covered by the default runtime lock or audit yet.

For npm updates, change package declarations using npm, commit package-lock.json, then run format/build/unit/browser checks and `npm audit --audit-level=high`. Do not automatically merge dependency PRs. Dependabot and scheduled workflows only become active as intended once these configuration files are present on the default branch; the current development branch does not change default-branch settings.

## Secret checking

`python scripts/check_secrets.py` scans tracked files with detect-secrets, with network verification disabled and value-free failure output. It also refuses tracked environment/database/key files. The reviewed baseline currently contains no findings; never regenerate it blindly to silence an alert. Inspect a suspected finding locally using `detect-secrets-hook --no-verify`, remove/rotate a real secret, or review a narrowly scoped false-positive exception. Generated dependency lock hashes are excluded from entropy scanning; do not introduce credentials into package index/registry URLs. Scans are not proof that Git history is secret-free.

## Packaging and release candidates

`make build` builds a wheel and source distribution and runs Twine metadata checks. `python scripts/verify_wheel.py artifacts/python/*.whl` installs the wheel into an isolated venv outside the checkout, then initializes and checks its database. Release-candidate workflows add SBOMs and SHA-256 checksums; they never publish anything automatically. See releasing.md and github-settings.md for the human release and repository administration steps.
