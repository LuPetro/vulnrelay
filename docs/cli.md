# Native installation and CLI

The CLI and API share the same database and validation rules. The UI is
optional; `vulnrelay monitor` is the separate long-running worker. Native
monitoring currently requires Unix file locking; native Windows operation and
PostgreSQL have not been validated for release.

## Install on Linux

From a fresh repository checkout with Python 3.12 or 3.13:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r backend/requirements-build.lock -r backend/requirements.lock
pip install --no-build-isolation --no-deps ./backend
cp .env.example .env
chmod 600 .env
vulnrelay init
vulnrelay config validate
vulnrelay start
```

Run `vulnrelay monitor` in a second terminal with the same virtual environment
and working directory. Native commands read `.env` from the current directory;
environment variables take precedence. Do not overwrite an existing `.env`.
`vulnrelay start` serves the local API; to use the optional UI natively, build
it from `frontend/` with a Node version supported by `frontend/package.json`
(22.22.2+ within 22.x, 24.15+ within 24.x, or 26+) and `npm ci && npm run build`, then start
the API from the repository root. Docker builds the frontend automatically.

## Check health and sources

```sh
vulnrelay --version
vulnrelay status --json
vulnrelay doctor
vulnrelay engine-health
vulnrelay check-nvd
vulnrelay queue status
```

`status` and `doctor` inspect stored state; `engine-health` requires a recent
worker heartbeat. `check-nvd` makes one read-only public API probe and does not
verify a complete synchronization. Other commands can call upstream APIs;
use `vulnrelay COMMAND --help` for current arguments.

Manual `vulnrelay sync`, `sync-kev`, `sync-osv` and `sync-opencve` use the
monitor lock. Stop the worker first and start it again after the command,
including when it fails. `sync --days N` applies its lookback to the initial
NVD run; it does not reset an established checkpoint.

## Configure assets, rules and destinations

```sh
vulnrelay catalog list --query postgres
vulnrelay catalog pack linux-server --group servers --preview
vulnrelay assets add examples/asset.json
vulnrelay assets list
vulnrelay connectors list
vulnrelay rules list
vulnrelay rules test RULE_ID
vulnrelay connectors test CONNECTOR_ID
vulnrelay history
```

Replace IDs with values from `list`. The connector test is **queued**; a
running monitor or `vulnrelay deliver` processes it when eligible. `deliver`
processes the next eligible queued event, not necessarily the one most recently
created. Full JSON examples and condition semantics are in
[configuration](configuration.md), [catalog](catalog.md),
[package list import](package-import.md) and [reports](reports.md).

For Compose, prefix commands with `docker compose exec vulnrelay`, for example
`docker compose exec vulnrelay vulnrelay assets list`. Files on the host are
not automatically available inside the container. Copy a JSON file first:

```sh
docker compose cp examples/asset.json vulnrelay:/tmp/asset.json
docker compose exec vulnrelay vulnrelay assets add /tmp/asset.json
```

Do not put actual secrets in JSON files or command arguments. Connector
configuration stores references to environment variables, whose values belong
in the private server environment. See [backup and upgrade](backup-and-upgrade.md)
before changing a database you depend on.
