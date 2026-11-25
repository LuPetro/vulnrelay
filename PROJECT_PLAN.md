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
- [x] NVD recovery with jittered request/run backoff, persisted provider deadlines and last-success/next-attempt explanations.
- [x] Persistent monitor schedule, database-specific monitor lock and graceful signal handling.
- [ ] Broader source normalization, conditional requests and longer-term performance testing.

## Notification MVP

- [x] Assets with vendor/product/CPE/explicit keyword identity, groups and context.
- [x] Conservative matching with method, confidence and evidence.
- [x] Nested AND/OR/NOT rules, missing-metric semantics and rule dry runs.
- [x] Persistent outbox, selected material-change deduplication, retry/backoff, expiring claims and failure inspection/retry.
- [x] Telegram connector, environment-only secret references, tests and bounded plain-text rendering.
- [x] Independent delivery pump while sources synchronize.
- [x] Configurable pacing, persisted Telegram cooldowns separate from failure retries, queue diagnostics and snapshot-based dismissals that retain deduplication.
- [x] Connector-specific weekly delivery windows, IANA timezones/DST, overnight schedules and off-hours queues without consumed attempts.
- [x] Live sent-count refresh, accessible compact rolling count and synchronized foreground pipeline ingress.
- [x] Reject inconsistent CPE/inventory versions and isolate invalid legacy assets.
- [x] Revalidate queued/retried alerts against current rules, assets and intelligence; visible cancellation and safe reconsideration after reactivation.
- [x] Document a controlled real Telegram acceptance test before extending features.
- [x] Document a fresh private-repository server installation with separate Compose project, image, port and data volume.
- [x] Operator confirmed a real Telegram connector test message (2026-11-15).
- [ ] Real operator-owned CVE-alert, duplicate protection and restart acceptance.
- [x] Offline technology catalog, editable environment-pack selection, CLI/API preview and atomic duplicate-safe import with preserved manual asset entry.
- [x] Expanded curated catalog: 87 technologies and 19 packs, with documented NVD provenance and conservative matching for libraries.
- [x] Opt-in OSV exact package/version queries and CVE-alias matching with persistent per-asset snapshots, source health and alert explanations.
- [x] Import supported unqualified package URLs with exact versions into OSV asset identities, with validation and UI preview.
- [x] Preview and atomically import up to 100 supported package URLs, preserving existing asset settings and avoiding concurrent duplicate imports.
- [x] Isolate OSV matching by asset snapshot and suppress timestamp-only re-notifications after establishing a compatible source-content baseline.
- [ ] Generic version ranges, qualified package URLs, non-CVE OSV advisories and inventory integration.
- [ ] Inventory JSON/YAML import/export and improved notification aggregation across matching assets.

## Local UI

- [x] Original vector branding and animated operational Overview with pause/reduced-motion controls and honest status/count semantics.
- [x] Faster uninterrupted packet handoffs and independent continuous loading indicators, preserving pause/reduced-motion behavior.
- [x] Isolated Overview design study with self-hosted typography, editorial grid, richer explanatory motion and mobile composition; operator approved broader design adoption after testing.

- [x] Shared Overview typography, paper/ink/green palette, ruled layouts and mobile/dark forms across all pages.
- [x] Overview and guided setup steps, asset CRUD, rule builder/testing, Telegram configuration/testing.
- [x] Redesigned shell/overview, catalog browser with category/search filters, import review, asset search and responsive dark/light design.
- [x] Source health, delivery history, local CVE search/details, dark/light theme and responsive styling.
- [x] Optional bearer token, Host checking and cross-origin mutation guard.
- [x] Browser E2E for setup, rule matching, failure/retry and a mobile viewport; automated accessibility checks on selected views.
- [ ] Broader browser coverage, manual accessibility audit and complete first-run activation wizard.
- [x] Consistent online SQLite backup and documented restore/upgrade rehearsal.
- [ ] Retention, automated backup management and remote-access hardening.

## Beyond the MVP

- [x] Add Discord and Slack webhook connectors with real delivery, tests and shared queue semantics; operator acceptance remains pending.
- [x] Add SMTP email delivery with authenticated STARTTLS, source-safe error handling and shared queue/scheduling semantics; live operator acceptance remains pending.
- [x] Add a versioned generic JSON webhook with optional HMAC signatures, stable event IDs, DNS pinning and shared delivery semantics; live operator acceptance remains pending.
- [x] Add ntfy and Gotify push connectors with secure token handling, rate limits and existing queue/schedule semantics; live operator acceptance remains pending.
- [ ] Add Matrix, Teams and Mattermost connectors where supported.
- [x] Add scheduled personal and global daily/weekly reports with coverage disclosure and persistent queue identities; live operator acceptance remains pending.
- [ ] Add digest grouping, historical missed-period catch-up options and alternative data-source coverage.
- [x] Add an opt-in AI settings tab with OpenAI, Anthropic and compatible APIs, model/language selection, connection tests, daily request limits, caching and labeled source-grounded alert summaries with safe fallback. One active configuration; live provider acceptance remains pending.
- [ ] Expand AI to multiple selectable profiles, additional native protocols, token/cost accounting and digest summaries after provider acceptance.
- [ ] Expand OSV to non-CVE records and qualified package URLs; consider lockfile/SBOM import after accurate matching works.
- [ ] Add lifecycle grouping, expiring suppression, optional critical out-of-hours escalation and clearer source health.
- [ ] Add CVE.org and expanded lifecycle/priority configuration.
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
- [x] Documentation index, English/German quickstarts, CLI and real-alert acceptance guides, and synthetic browser screenshots.
- [ ] Owner review of the name: another security product uses VulnRelay; assess domain/trademark availability before public branding.
- [ ] Audit all branches, tags, Git history, PRs/issues and Actions logs/artifacts for sensitive content; review licensing and source attribution.
- [ ] Establish and verify a confidential security-reporting route before public release.
- [ ] Owner review of default-branch protections, private security reporting and public visibility before publication; these are not activated by files alone.
