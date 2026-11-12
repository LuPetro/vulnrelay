# VulnRelay

Self-hosted vulnerability notification engine. **Early development:** this foundation does not yet ingest CVEs or send notifications.

## Development

Requires Python 3.12+ with venv/pip. From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e 'backend[dev]'
alembic -c backend/alembic.ini upgrade head
vulnrelay start
```

Check `http://127.0.0.1:8080/health`, run `vulnrelay status --json`, `vulnrelay config validate`, and `pytest backend/tests`. Configure deployment with `VULNRELAY_` environment variables; `.env.example` documents defaults. Export them in a native shell: the application does not automatically read `.env`.

With Docker Compose, run `docker compose up --build`; the database is stored in a named volume and the port is bound to localhost. The container listens on its internal network interface for port forwarding. Do not expose it remotely: authentication is not implemented.

See [PROJECT_PLAN.md](PROJECT_PLAN.md) and [STATE.md](STATE.md) for scope and progress. Licensed under Apache-2.0.
