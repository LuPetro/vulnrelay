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

78 backend tests pass, covering sources, matching, missing metrics, API guards/authentication, the complete API-to-queue-to-mocked-Telegram path, deduplication, material changes, retries, claim recovery, schedule persistence, source isolation and independent delivery. Ruff passes. TypeScript/Vite build, one frontend form test and the expanded Chromium scenario pass. The browser flow includes rejected CPE/version conflicts, setup, rule evidence, delivery failure/retry, cancellation after rule disabling and a mobile viewport, with automated WCAG checks on selected views. Wheel/sdist metadata checks and an isolated Docker API/UI/worker/restart/backup smoke run pass. The previous live source snapshot included 12,495 NVD records and 4,387 enriched EPSS records. No real Telegram delivery has been performed because no operator credentials/destination are configured. Broader/manual accessibility testing and PostgreSQL E2E are still pending. Remote CI outcomes must be checked separately for each pushed commit.

## Next priorities

Follow docs/first-test.md with real operator-owned Telegram credentials before extending features. Keep release status alpha until acceptance criteria are independently verified. Afterwards prioritize version applicability, inventory import/export, notification aggregation and retention/backups. Optional AI is deferred.

Git is configured locally as the connected LuPetro account with its GitHub noreply address. GitHub development history differs from local history because uploads use the GitHub connector; reconcile before a normal Git push. The development-agent timer is not active. The application's own monitoring worker is separate and runs through Docker Compose.

## First-test and open-source hardening

Added hash-locked Python runtime/build/developer environments, pinned CI actions/base images, a Python 3.12/3.13 CI matrix, branch coverage with a 75% floor (local measured 78.83%), format/type checks, wheel/sdist/Twine verification and an isolated built-wheel installation. Local Python runtime/developer and npm audits report no known vulnerabilities; an offline secret baseline has no findings and a synthetic-token rejection was checked. These scans do not certify security or history. New GitHub job outcomes must be checked on the pushed commit.

Added request-size and malformed-input safeguards, efficient paged correlation and an empty-configuration fast path, schema readiness and a recent worker heartbeat, private new SQLite files, online backups and restore/upgrade documentation. A consistent pre-readiness backup of the local deployment was made inside its existing volume. An isolated Compose project passed packaged API/UI/worker health, restart persistence and backup tests and then removed only its own test resources.

Community/release files now include governance, code of conduct, CODEOWNERS, issue and PR templates, changelog, third-party notices and an unpublished release-candidate workflow. Dependency-update and scheduled-audit activation depends on the configuration reaching the default branch; branch rules, GitHub security features and public visibility remain owner administration tasks. No publication or automatic merge has been enabled.

## Alert correctness fixes and acceptance procedure

New asset writes reject conflicting inventory/CPE versions with a static, safe API error. Invalid legacy asset documents are excluded without preventing other assets from monitoring, and unchecked inconsistent models cannot return confirmed matches. General version ranges remain unsupported.

Before every alert attempt (pending, retry and recovered lease), delivery loads the current rule, asset, destination selection and stored CVE and uses the same deterministic evaluation as enqueueing. Obsolete alerts become cancelled with a recorded reason and no Telegram HTTP request. Eligible messages refresh their content/evidence/format. Normal evaluation may reconsider cancelled events when their configuration becomes eligible again; sent-event deduplication remains intact. Test messages still work independently of rules. An HTTP request already in flight cannot be recalled.

Added regression coverage for 12 eligibility changes across three queue states, reactivation/deduplication, refreshed content, legacy conflicts and rejected create/update operations. Current local branch-inclusive coverage is 80.58% (75% gate). Matching evidence is reused across rules during correlation to retain the previous per-asset matching cost. docs/first-test.md describes controlled real delivery, deduplication, restart and rule-disable checks. Docker credential changes require container recreation, not just restart. A real Telegram acceptance result is still pending.
