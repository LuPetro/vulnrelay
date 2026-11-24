# Changelog

Changes are recorded here before a release is published. No stable version has been released.

## Unreleased — 0.1.0-alpha.0

### Fixed

- Recover from transient NVD failures with jittered request/recovery backoff and persisted provider deadlines; show last success and next attempt alongside failure details.
- Speed up Overview packet motion, remove endpoint holds and animate loading indicators continuously, independently of packet arrivals.

- Synchronize pipeline ingress at a shared merge point, render packets above nodes/lines, align registration marks and simplify the inventory inlet.
- Separate Telegram 429 cooldowns from bounded delivery failures, retain provider deadlines across restart/new destinations, share alias pacing and remove the blind post-send worker delay.

- Replace generic NVD failure text with safe HTTP, timeout, connectivity, malformed-response, checkpoint and database diagnostics in source status, logs and manual sync output. Retain successful state on failure and clear errors after recovery.
- Reject conflicting inventory/CPE versions and skip invalid legacy assets without stopping other monitoring.
- Revalidate alerts before delivery/retry, cancel obsolete alerts visibly, refresh eligible message content and allow cancelled events to be reconsidered after reactivation.

### Added

- Import supported unqualified package URLs with exact versions into OSV asset identities via GUI, API or CLI, including atomic, duplicate-aware list imports with preview.
- ntfy and Gotify push connectors with environment-only token references, private-server opt-in and shared queue, scheduling and rate-limit handling.
- Generic JSON webhook connector with optional HMAC-SHA256 signatures, stable event IDs, destination restrictions and persistent retry/queue semantics.
- SMTP email connector with certificate-verified STARTTLS, pinned DNS, server-side credential references and delivery-hour support.
- Opt-in OSV.dev checks for declared exact package versions in six ecosystems, CVE-alias matching, per-asset health and conservative source attribution.
- Daily and weekly global or asset-relevant reports, timezone-aware scheduling, source-coverage disclosure and UI/CLI previews.
- Optional AI alert summaries with a dedicated settings tab, OpenAI/Anthropic/compatible protocols, configurable model/language, daily request cap and safe fallback.
- Discord and Slack webhook connectors sharing the existing persistent queue and delivery hours.

- Connector delivery hours with weekly/overnight windows, IANA timezones and daylight-saving support. Held alerts keep their queue state and retry budgets; queue diagnostics show the next permitted attempt.
- Expand the offline catalog to 87 technologies and 19 packs with documented NVD identities, including libraries and homelab/network/identity stacks.
- Apply the accepted Overview visual identity across the workspace, with shared typography, light/dark colors, ruled layouts and responsive forms.

- Configurable Telegram send intervals, queue diagnostics/clear controls in Overview and Connectors plus CLI/API. Discarded events retain their deduplication keys.
- Independently refreshed sent totals and an accessible rolling counter with k notation above 1,000.

- Overview-only editorial design study: locally served IBM Plex typography, ruled coverage/source/inventory layouts, restrained colors and coordinated packet/matching/filter/delivery motion with a separately composed mobile diagram. Other application pages retain their design.
- Read-only `vulnrelay check-nvd [--json]` connectivity probe that works while monitoring, reports key presence without revealing it and does not change synchronization state.
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
- Generic version ranges, qualified PURLs, OSV advisories without a CVE alias, additional connector types, richer digest options and multiple AI profiles remain unfinished. Live provider acceptance is still needed for new connectors and AI.
- Remote exposure and PostgreSQL require further hardening and validation.
