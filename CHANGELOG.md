# Changelog

Changes are recorded here before a release is published. No stable version has been released.

## Unreleased — 0.1.0-alpha.0

### Fixed

- Reject conflicting inventory/CPE versions and skip invalid legacy assets without stopping other monitoring.
- Revalidate alerts before delivery/retry, cancel obsolete alerts visibly, refresh eligible message content and allow cancelled events to be reconsidered after reactivation.

### Added

- Optional OpenCVE public Knowledge Base adapter, cached manual UI/CLI/API lookups, bounded opt-in background enrichment, separate assessments and source attribution without an account.
- Incremental NVD ingestion, CISA KEV snapshots and FIRST EPSS enrichment with source provenance.
- Explicit asset matching, nested explainable rules and persistent Telegram notification delivery.
- Optional local React configuration UI, source/queue history, CLI and Docker Compose deployment.
- API access safeguards, database migrations, failure recovery and mocked end-to-end delivery tests.
- Contributor and security policies, dependency locks/audits, CI gates and release-candidate preparation.
- Consistent online SQLite backup, schema readiness and monitoring heartbeat checks.

### Known limitations

- Alpha status: real operator-owned Telegram delivery still needs validation.
- Generic version ranges, package matching, additional connectors, digests and optional AI are unfinished.
- Remote exposure and PostgreSQL require further hardening and validation.
