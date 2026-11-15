# Changelog

Changes are recorded here before a release is published. No stable version has been released.

## Unreleased — 0.1.0-alpha.0

### Fixed

- Reject conflicting inventory/CPE versions and skip invalid legacy assets without stopping other monitoring.
- Revalidate alerts before delivery/retry, cancel obsolete alerts visibly, refresh eligible message content and allow cancelled events to be reconsidered after reactivation.

### Added

- Original SVG logo/wordmarks and favicon; redesigned Overview with motion controls, a source-to-delivery illustration, actionable counts, source/queue attention states and responsive asset-group cards. Motion respects reduced-motion preferences and hidden tabs.

- Searchable bundled catalog with 50 technologies, ten editable starter-pack selections, context selection, read-only preview and atomic/idempotent imports through UI, API and CLI.
- Redesigned application shell and overview, dedicated catalog workspace, asset search, responsive light/dark layouts and browser coverage for catalog onboarding.
- Optional OpenCVE public Knowledge Base adapter, cached manual UI/CLI/API lookups, bounded opt-in background enrichment, separate assessments and source attribution without an account.
- Incremental NVD ingestion, CISA KEV snapshots and FIRST EPSS enrichment with source provenance.
- Explicit asset matching, nested explainable rules and persistent Telegram notification delivery.
- Optional local React configuration UI, source/queue history, CLI and Docker Compose deployment.
- API access safeguards, database migrations, failure recovery and mocked end-to-end delivery tests.
- Contributor and security policies, dependency locks/audits, CI gates and release-candidate preparation.
- Consistent online SQLite backup, schema readiness and monitoring heartbeat checks.

### Known limitations

- Alpha status: an operator confirmed a real Telegram test message; controlled CVE-alert, deduplication and restart acceptance remain open.
- Generic version ranges, package matching, additional connectors, digests and optional AI are unfinished.
- Remote exposure and PostgreSQL require further hardening and validation.
