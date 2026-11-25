# Project governance

VulnRelay is currently maintained by the repository owner, LuPetro. It is alpha software being prepared for an open-source release; repository visibility is controlled separately. Contributions are Apache-2.0 and reviewed before incorporation into the default branch.

## Decisions and review

Use issues to describe user problems and acceptance criteria, and pull requests for reviewable changes. Significant changes to matching semantics, delivery guarantees, security boundaries, storage or licensing require an explicit design discussion. Small fixes can be reviewed directly. Human maintainers decide release readiness; passing automated checks is necessary but does not prove production safety.

CODEOWNERS identifies review responsibility. Branch rules must be configured in GitHub to enforce it. No bot automatically merges updates or publishes releases. A maintainer should inspect dependency major upgrades, migration changes and new outbound destinations. New maintainers are added by the owner after a documented history of contributions and agreement to the security policy.

## Priorities

Correct matching, useful notifications, predictable installation and data safety come before integrations or AI features. PROJECT_PLAN.md describes priorities and STATE.md records the actual implementation and evidence. Unfinished features stay marked unfinished.

## Releases

Use SemVer-style prerelease labels for alpha/beta candidates. Keep CHANGELOG.md accurate and maintain compatibility notes. Release candidates must pass tests, security audits, packaging checks and installation verification. A real configured Telegram destination must be exercised before the first supported release. See docs/releasing.md. No service-level agreement or guaranteed support window exists for alpha versions.
