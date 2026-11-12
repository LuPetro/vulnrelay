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
- [x] Persistent monitor schedule, database-specific monitor lock and graceful signal handling.
- [ ] Broader source normalization, conditional requests and longer-term performance testing.

## Notification MVP

- [x] Assets with vendor/product/CPE/explicit keyword identity, groups and context.
- [x] Conservative matching with method, confidence and evidence.
- [x] Nested AND/OR/NOT rules, missing-metric semantics and rule dry runs.
- [x] Persistent outbox, selected material-change deduplication, retry/backoff, expiring claims and failure inspection/retry.
- [x] Telegram connector, environment-only secret references, tests and bounded plain-text rendering.
- [x] Independent delivery pump while sources synchronize.
- [ ] Real operator-owned Telegram end-to-end validation (no credentials supplied yet).
- [ ] Generic version applicability, packages/PURLs and OSV matching.
- [ ] Inventory JSON/YAML import/export and improved notification aggregation across matching assets.

## Local UI

- [x] Overview and guided setup steps, asset CRUD, rule builder/testing, Telegram configuration/testing.
- [x] Source health, delivery history, local CVE search/details, dark/light theme and responsive styling.
- [x] Optional bearer token, Host checking and cross-origin mutation guard.
- [ ] Full browser E2E/accessibility audit and complete first-run activation wizard.
- [ ] Retention, backup management and remote-access hardening.

## Beyond the MVP

- [ ] Discord, SMTP and generic webhook connectors; connector development protocol.
- [ ] Daily digests, CVE.org and expanded lifecycle/priority configuration.
- [ ] Optional AI providers, budgets, summaries, translation and evidence-based safe fallback.
- [ ] PostgreSQL integration validation, release artifacts and security review.

## Development automation

- [x] Bounded development runner with simulated CLI validation and an optional timer template.
- [ ] Schedule activation is deferred; current work focuses on the application.
