# VulnRelay

**Know what matters. Get notified.**

VulnRelay is an Apache-2.0, self-hosted vulnerability notification engine. Declare the products you run, connect Telegram, Discord or Slack, and choose rules based on CVSS, EPSS, known exploitation and asset context. The optional local React interface configures the engine; a separate worker keeps monitoring after you close the browser. No cloud account or AI is required.

**Current status: alpha.** The core path is implemented and tested with mocked Telegram delivery: public intelligence → explicit asset matching → explainable rules → persistent delivery queue. An operator has confirmed a real Telegram test message; controlled CVE-alert, duplicate-prevention and restart acceptance remain separate checks. This is not yet a v1 or production release.

## Start with Docker

For a fresh installation alongside an existing deployment, use the [separate server test installation guide (German)](docs/server-test-installation.md). It uses its own directory, Compose project, image, port and empty database.

```sh
cp .env.example .env
# Put your Telegram bot token in .env, then:
docker compose up --build -d
```

Open **http://localhost:8080**. Add an asset, add a Telegram connector with your chat ID, create a rule, and queue a test message. The monitoring worker synchronizes NVD/CISA, refreshes EPSS daily, evaluates rules, and sends queued messages. The database and schedules live in a persistent Docker volume. After changing `.env`, recreate both containers with `docker compose up -d --force-recreate`; a plain restart does not reload container environment variables. Ports bind to localhost; do not publish this alpha to the Internet.

The first source synchronization can take several minutes, especially without an NVD API key. Sources fail independently. The UI shows saved source checkpoints, errors, delivery states and the last engine heartbeat. A saved checkpoint is not a real-time guarantee of source availability.

## What works

- NVD API 2.0 incremental ingestion, checkpoints, pagination, bounded retry/backoff, and original record preservation.
- CISA KEV authoritative snapshots with validation, rollback on invalid catalogs and stale-catalog rejection.
- Daily EPSS CSV enrichment of locally stored CVEs, plus individual FIRST API lookups.
- Optional OpenCVE Knowledge Base enrichment, manual UI/CLI lookups, conditional caching and separate source assessments.
- Assets identified by vendor, product, vendor/product, CPE 2.3 or explicit keyword; group, importance, exposure and tags.
- Searchable offline catalog of 87 technologies and 19 customizable environment packs, with preview, atomic import and duplicate protection. Manual asset entry remains available.
- Nested AND/OR/NOT rules with missing-data semantics and machine-readable explanations.
- Telegram, Discord and Slack destinations, compact/detailed plain-text messages, queued test notifications and delivery history. Discord and Slack use server-side webhook secret references.
- Durable queue, expiring delivery claims, bounded retries, deduplication and re-notification on selected material changes.
- Local configuration UI with dark/light themes, rule builder, rule tests and searchable CVE history.
- Headless CLI, SQLite WAL, packaged database migrations, optional PostgreSQL plumbing, CI tests and Docker deployment.

## Matching and metrics

Product and keyword matches are **potential**. An installed version with unverified applicability is **unknown**. Only a literal vulnerable CPE with an explicit version in an unconstrained OR branch is eligible for **confirmed** matching. Version ranges, environmental AND constraints and keyword-only evidence never become confirmed claims. Generic version-range evaluation, package ecosystems, OSV and PURLs remain unfinished.

CVSS is severity, EPSS is an exploitation probability estimate, and KEV records known exploitation. Missing metrics stay unknown, including under NOT. EPSS dates and KEV catalog dates are shown; stale values are not silently replaced with zero. The custom rule engine does not claim an officially validated risk score.

A successful initial run evaluates the synchronized window, so it can notify about existing relevant records. Default NVD bootstrap covers the last seven modified days; the KEV catalog includes historical CVEs. Adjust bootstrap with `vulnrelay sync --days 30` before starting the native monitor. No full historical NVD backfill is implied.

## Native Python installation

Python 3.12+ with pip/venv is required:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r backend/requirements-build.lock -r backend/requirements.lock
pip install --no-build-isolation --no-deps ./backend
cp .env.example .env
vulnrelay init
vulnrelay start
# In a second terminal with the same environment:
vulnrelay monitor
```

The GUI shares the Overview’s local typography, paper/ink palette and ruled layouts across configuration, catalog, source history and settings, with responsive light/dark views. The GUI is optional. Build it with Node 22+: `cd frontend && npm ci && npm run build`. The API serves `./frontend/dist` when present. During frontend development, `npm run dev` proxies `/api` to localhost:8080. Native commands read `.env` from the working directory; environment variables override it.

## CLI examples

```sh
vulnrelay doctor
vulnrelay catalog list --query postgres
vulnrelay catalog pack linux-server --group servers --environment production --preview
vulnrelay status --json
vulnrelay queue status
vulnrelay check-nvd
vulnrelay sync --days 7
vulnrelay sync-kev
vulnrelay lookup-epss CVE-2021-44228
vulnrelay cve CVE-2021-44228
vulnrelay assets add examples/asset.json
vulnrelay connectors add examples/telegram.json
vulnrelay assets list
vulnrelay connectors list
# Insert the returned connector ID into your rule JSON:
vulnrelay rules add your-rule.json
vulnrelay rules test RULE_ID
vulnrelay evaluate --enqueue
vulnrelay connectors test CONNECTOR_ID
vulnrelay deliver
vulnrelay history
vulnrelay monitor --once --no-sync
```

See [Telegram setup](docs/telegram.md), [Discord and Slack setup](docs/webhook-connectors.md), [rules and assets](docs/configuration.md), [architecture](docs/architecture.md), [troubleshooting](docs/troubleshooting.md), [security](SECURITY.md), and [contributing](CONTRIBUTING.md). Local API documentation is at `/docs`; mutations require `X-VulnRelay-Request: 1` and the bearer token if configured.

In **Connectors → Edit → Delivery hours**, choose unrestricted delivery or weekly windows, such as Monday–Friday 07:00–17:00 in Europe/Vienna. Outside those hours, alerts and test messages stay queued without consuming delivery attempts. Monitoring continues, and current applicability is checked before sending. Multiple windows, overnight hours and daylight-saving changes are supported. See [connector delivery hours](docs/connector-schedules.md) and [a CLI-ready example](examples/telegram-workhours.json).

For easier inventory setup, open **Catalog**, choose individual technologies or an environment pack, remove components you do not run, then review and add your selection. See [catalog, duplicate handling, freshness and update instructions](docs/catalog.md). Existing rules may apply to new assets; product matches still require installed-version verification.

The Overview shows your engine heartbeat, source status, message history and asset groups. Its illustrative animation can be paused and respects reduced-motion preferences. See [Overview behavior and SVG logo files](docs/brand.md).

The current [Overview design study](docs/overview-design.md) uses locally served IBM Plex typography, a ruled operating layout and explanatory signal-path motion. It is scoped to this page for review before changing the rest of the interface.

For [OpenCVE enrichment](docs/opencve.md), open a CVE and choose **Load OpenCVE details**, or run `vulnrelay lookup-opencve CVE-2021-44228`. Background enrichment is opt-in with `VULNRELAY_OPENCVE_ENABLED=true`. Existing NVD scores remain primary; OpenCVE assessments are stored separately. The integration reads OpenCVE's public KB and requires no account.

## Delivery guarantees and remaining work

Delivery is **at least once**. A crash after Telegram accepted a message and before the database recorded success can cause a repeat; Telegram does not provide an idempotency key for `sendMessage`. Non-rate delivery failures have a six-attempt retry budget with backoff. Telegram rate-limit responses use the provider cooldown without consuming that budget. Per-connector spacing defaults to 3.1 seconds and is configurable. Expiring claims and terminal failures remain visible. An unchanged alert is not queued again for the same CVE, asset, rule and destination. KEV changes, CVSS/status changes, a new ten-percentage-point EPSS band, CPE evidence changes and changed NVD patch references can create another event. Disabling change notifications keeps one event per identity. Multiple matching assets can produce separate, explicitly attributed alerts.

Still planned: arbitrary version applicability and package matching, additional connector types, digests, AI, inventory import/export, retention and automated backup management, remote-access security and broader release validation. PostgreSQL code paths have not been validated end to end. Windows native monitoring is unsupported because the monitor uses Unix file locking. See [PROJECT_PLAN.md](PROJECT_PLAN.md) and [STATE.md](STATE.md).

The optional [development agent runner](docs/agent-runner.md) is separate from CVE monitoring and is not scheduled automatically.

Source references: [NVD API](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS data](https://www.first.org/epss/data), [Telegram Bot API](https://core.telegram.org/bots/api#sendmessage). This product uses NVD data but is not endorsed or certified by NVD.

## Before testing or contributing

Use the [testing and development guide](docs/development.md) for locked dependencies, style/type checks, coverage, browser E2E tests, security audits and package verification. Read the [backup and upgrade procedure](docs/backup-and-upgrade.md) before storing an inventory you depend on. `/health` checks connectivity; `/ready` checks the database revision; `vulnrelay engine-health` checks the monitoring worker heartbeat. `vulnrelay --version` reports the installed backend version.

For your first real Telegram acceptance run, follow the [step-by-step checklist (German)](docs/first-test.md). It covers a real test message and CVE alert, matching evidence, duplicate prevention, restart persistence and cancellation after disabling a rule. A rule/asset/CVE is revalidated before every queued alert attempt; an obsolete alert becomes `cancelled` with a visible reason.

The [changelog](CHANGELOG.md), [governance](GOVERNANCE.md), [community guidelines](CODE_OF_CONDUCT.md), issue/PR templates and [manual release process](docs/releasing.md) prepare the project for open-source collaboration. Repository visibility, branch rules and GitHub security features are operator settings; see [the administration checklist](docs/github-settings.md). No public publication or package upload is automatic.

See [delivery queue controls and Telegram pacing](docs/delivery-queue.md) for configurable send intervals, provider cooldowns, backlog clearing and precise sent-count semantics.
