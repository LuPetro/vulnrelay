# Current state

VulnRelay now has an integrated alpha notification engine and optional React/TypeScript/Vite/Tailwind local UI. It is not a v1 release.

## Implemented

- Packaged migrations through 0005; init/status/doctor; SQLite WAL; .env support; non-root Docker API/UI plus monitoring worker and persistent volume.
- Incremental NVD ingestion stages downloads before a short atomic write transaction. CISA snapshots preserve valid prior data on failure. FIRST EPSS enriches local CVEs daily from the bulk feed, supports bounded same-host HTTPS redirects, and keeps on-demand API lookup.
- Persistent monitoring schedule and per-database lock; independent delivery thread; source failure isolation; structured application logging without provider exception URLs.
- Validated asset/rule/Telegram CRUD shared between CLI and API. Matching returns confidence and evidence; generic version ranges remain unverified. Rule evaluation is three-valued and supports nested AND/OR/NOT.
- Deduplicated persistent outbox, selected material-change re-notification, destination cooldowns, expiring claims, bounded retries, failure history and explicit operator retry. At-least-once semantics; not exactly once.
- Local UI: setup guidance, overview/source health, assets, nested rule builder, Telegram connector tests, rule dry runs, CVE search/details, delivery history/retry, dark/light themes and optional API token in browser memory.
- Configuration API has Host validation, cross-origin mutation checks and optional bearer protection. Remote deployment is unsupported.

## Verification

35 backend tests pass, covering sources, matching, missing metrics, API guards/authentication, the complete API-to-queue-to-mocked-Telegram path, deduplication, material changes, retries, claim recovery, schedule persistence, source isolation and independent delivery. Ruff passes. TypeScript/Vite build, one frontend form test, and one Chromium browser scenario pass. The browser scenario covers setup, rule evidence, delivery failure/retry and a mobile viewport, with automated WCAG checks on selected views. A wheel builds with packaged migrations. Docker API and worker started successfully; UI, health and overview were checked. The live monitor has ingested 12,495 NVD records and reported successful NVD, CISA and EPSS synchronization; the native bulk EPSS check enriched 4,387 local records. No real Telegram delivery has been performed because no operator credentials/destination are configured. Desktop/mobile fixture screenshots were visually reviewed. Broader/manual accessibility testing and PostgreSQL E2E are still pending. CI configuration is present; remote CI outcomes must be checked separately.

## Next priorities

Validate real Telegram setup when credentials are provided; add inventory import/export, better version applicability, broader browser E2E/accessibility tests, notification aggregation, retention/backups and additional connectors/digests. Keep release status alpha until acceptance criteria are independently verified. Optional AI is unfinished and unnecessary for the current engine.

Git is configured locally as the connected LuPetro account with its GitHub noreply address. GitHub development history differs from local history because uploads use the GitHub connector; reconcile before a normal Git push. The development-agent timer is not active. The application's own monitoring worker is separate and runs through Docker Compose.

## First-test and open-source hardening

Added hash-locked Python runtime/build/developer environments, pinned CI actions/base images, a Python 3.12/3.13 CI matrix, branch coverage with a 75% floor (local measured 78.83%), format/type checks, wheel/sdist/Twine verification and an isolated built-wheel installation. Local Python runtime/developer and npm audits report no known vulnerabilities; an offline secret baseline has no findings and a synthetic-token rejection was checked. These scans do not certify security or history. New GitHub job outcomes must be checked on the pushed commit.

Added request-size and malformed-input safeguards, efficient paged correlation and an empty-configuration fast path, schema readiness and a recent worker heartbeat, private new SQLite files, online backups and restore/upgrade documentation. A consistent pre-readiness backup of the local deployment was made inside its existing volume. An isolated Compose project passed packaged API/UI/worker health, restart persistence and backup tests and then removed only its own test resources.

Community/release files now include governance, code of conduct, CODEOWNERS, issue and PR templates, changelog, third-party notices and an unpublished release-candidate workflow. Dependency-update and scheduled-audit activation depends on the configuration reaching the default branch; branch rules, GitHub security features and public visibility remain owner administration tasks. No publication or automatic merge has been enabled.
