# VulnRelay roadmap

The first release must deliver real asset-relevant alerts and recover after restart. Alpha implementation is not equivalent to release readiness.

## Foundation

- [x] FastAPI, environment/.env configuration, SQLAlchemy, SQLite WAL, packaged Alembic migrations.
- [x] Native init/status/doctor CLI and non-root Docker build with persistent storage.
- [x] CI for backend, frontend and packaged container smoke checks.

## Intelligence

- [x] NVD incremental ingestion, pagination, checkpoints, bounded retry and atomic commit.
- [x] CISA KEV validated authoritative snapshots with stale-feed rejection.
- [x] FIRST EPSS individual lookup and daily CSV enrichment of local CVEs.
- [x] Source health, failure isolation and original source records.
- [x] Actionable secret-safe NVD failure diagnostics and a read-only CLI connectivity probe independent of the monitor lock.
- [x] Optional OpenCVE public KB lookups and bounded enrichment, independent assessments, conditional requests, UI/CLI/API and provider failure tests.
- [x] Persistent monitor schedule, database-specific monitor lock and graceful signal handling.
- [ ] Broader source normalization, conditional requests and longer-term performance testing.

## Notification MVP

- [x] Assets with vendor/product/CPE/explicit keyword identity, groups and context.
- [x] Conservative matching with method, confidence and evidence.
- [x] Nested AND/OR/NOT rules, missing-metric semantics and rule dry runs.
- [x] Persistent outbox, selected material-change deduplication, retry/backoff, expiring claims and failure inspection/retry.
- [x] Telegram connector, environment-only secret references, tests and bounded plain-text rendering.
- [x] Independent delivery pump while sources synchronize.
- [x] Reject inconsistent CPE/inventory versions and isolate invalid legacy assets.
- [x] Revalidate queued/retried alerts against current rules, assets and intelligence; visible cancellation and safe reconsideration after reactivation.
- [x] Document a controlled real Telegram acceptance test before extending features.
- [x] Document a fresh private-repository server installation with separate Compose project, image, port and data volume.
- [x] Operator confirmed a real Telegram connector test message (2026-11-15).
- [ ] Real operator-owned CVE-alert, duplicate protection and restart acceptance.
- [x] Offline technology catalog, editable environment-pack selection, CLI/API preview and atomic duplicate-safe import with preserved manual asset entry.
- [ ] Generic version applicability, packages/PURLs and OSV matching.
- [ ] Inventory JSON/YAML import/export and improved notification aggregation across matching assets.

## Local UI

- [x] Original vector branding and animated operational Overview with pause/reduced-motion controls and honest status/count semantics.

- [x] Overview and guided setup steps, asset CRUD, rule builder/testing, Telegram configuration/testing.
- [x] Redesigned shell/overview, catalog browser with category/search filters, import review, asset search and responsive dark/light design.
- [x] Source health, delivery history, local CVE search/details, dark/light theme and responsive styling.
- [x] Optional bearer token, Host checking and cross-origin mutation guard.
- [x] Browser E2E for setup, rule matching, failure/retry and a mobile viewport; automated accessibility checks on selected views.
- [ ] Broader browser coverage, manual accessibility audit and complete first-run activation wizard.
- [x] Consistent online SQLite backup and documented restore/upgrade rehearsal.
- [ ] Retention, automated backup management and remote-access hardening.

## Beyond the MVP

- [ ] Discord, SMTP and generic webhook connectors; connector development protocol.
- [ ] Daily digests, CVE.org and expanded lifecycle/priority configuration.
- [ ] Optional AI providers, budgets, summaries, translation and evidence-based safe fallback.
- [ ] PostgreSQL integration validation, release artifacts and security review.

## Development automation

- [x] Stop the previous development deployment and record the boundary between isolated development tests and the operator-owned long-running installation.
- [x] Bounded development runner with simulated CLI validation and an optional timer template.
- [ ] Schedule activation is deferred; current work focuses on the application.

## Before-first-test and open-source preparation

- [x] Hash-locked runtime/build/developer dependencies and immutable base/action pins.
- [x] Read-only, time-bounded CI; Python version matrix, coverage threshold, wheel/source metadata checks, browser and isolated container restart tests.
- [x] Known-vulnerability audits, offline secret checks, metadata/lock/workflow policy checks.
- [x] Schema readiness, worker heartbeat health, bounded API bodies and private SQLite/backup creation.
- [x] Governance, code of conduct, CODEOWNERS, issue/PR templates, dependency-update configuration, changelog and third-party notices.
- [x] Manual unpublished release-candidate artifact/SBOM/checksum workflow.
- [ ] Owner review of default-branch protections, private security reporting and public visibility before publication; these are not activated by files alone.
