# Current state

VulnRelay now has an integrated alpha notification engine and optional React/TypeScript/Vite/Tailwind local UI. It is not a v1 release. Estate Atlas is outside this project and was not modified.

## Implemented

- Packaged migrations through 0005; init/status/doctor; SQLite WAL; .env support; non-root Docker API/UI plus monitoring worker and persistent volume.
- Incremental NVD ingestion stages downloads before a short atomic write transaction. CISA snapshots preserve valid prior data on failure. FIRST EPSS enriches local CVEs daily from the bulk feed, supports bounded same-host HTTPS redirects, and keeps on-demand API lookup.
- Persistent monitoring schedule and per-database lock; independent delivery thread; source failure isolation; structured application logging without provider exception URLs.
- Validated asset/rule/Telegram CRUD shared between CLI and API. Matching returns confidence and evidence; generic version ranges remain unverified. Rule evaluation is three-valued and supports nested AND/OR/NOT.
- Deduplicated persistent outbox, selected material-change re-notification, destination cooldowns, expiring claims, bounded retries, failure history and explicit operator retry. At-least-once semantics; not exactly once.
- Local UI: setup guidance, overview/source health, assets, nested rule builder, Telegram connector tests, rule dry runs, CVE search/details, delivery history/retry, dark/light themes and optional API token in browser memory.
- Configuration API has Host validation, cross-origin mutation checks and optional bearer protection. Remote deployment is unsupported.

## Verification

28 backend tests pass, covering sources, matching, missing metrics, API guards/authentication, the complete API-to-queue-to-mocked-Telegram path, deduplication, material changes, retries, claim recovery, schedule persistence, source isolation and independent delivery. Ruff passes. TypeScript/Vite build and one frontend form smoke test pass. A wheel builds with packaged migrations. Docker API and worker started successfully; UI, health and overview were checked. The live monitor has ingested 12,495 NVD records and reported successful NVD, CISA and EPSS synchronization; the native bulk EPSS check enriched 4,387 local records. No real Telegram delivery has been performed because no operator credentials/destination are configured. No full browser visual/accessibility test or PostgreSQL E2E suite has run. CI configuration is present; remote CI outcomes must be checked separately.

## Next priorities

Validate real Telegram setup when credentials are provided; add inventory import/export, better version applicability, broader browser E2E/accessibility tests, notification aggregation, retention/backups and additional connectors/digests. Keep release status alpha until acceptance criteria are independently verified. Optional AI is unfinished and unnecessary for the current engine.

Git is configured locally as the connected LuPetro account with its GitHub noreply address. GitHub development history differs from local history because uploads use the GitHub connector; reconcile before a normal Git push. The development-agent timer is not active. The application's own monitoring worker is separate and runs through Docker Compose.
