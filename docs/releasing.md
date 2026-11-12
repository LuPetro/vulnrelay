# Release preparation

The current version is an alpha candidate, not a supported stable release. Do not publish without explicit owner authorization.

1. Complete the acceptance criteria in PROJECT_PLAN.md, including a real Telegram setup, an installation from a clean machine, restart recovery and backup/restore rehearsal. Record limitations rather than marking mocked integration tests as real delivery.
2. Update backend/pyproject.toml and frontend/package.json together. Python `0.1.0a0` and frontend `0.1.0-alpha.0` express the same prerelease. Run scripts/check_release.py. Keep root and packaged Apache licenses identical.
3. Regenerate and review dependency locks following docs/development.md. Resolve security audit findings or document an explicit, time-bounded maintainer decision. Do not silently suppress vulnerable dependencies.
4. Update CHANGELOG.md, compatibility notes and installation docs. Review source-provider attribution, notification guarantees, security policy and third-party dependency license notices. Review generated SBOMs before public distribution.
5. Require green CI and Security checks on the candidate commit. Dispatch the Release candidate workflow, which validates, builds the Python wheel/sdist and frontend bundle and attaches checksums/SBOMs as private workflow artifacts. It does not publish a GitHub release, package or container.
6. Install the wheel into a clean Python environment and test the Compose candidate. Keep persistent volume backups. Rehearse a restore to a fresh database before upgrading a real installation.
7. Only after human approval, tag the reviewed commit, publish through separately authorized credentials, and attach the validated artifacts and release notes. Never modify an already-published tag or replace an artifact silently. A fix requires a new version.

Stable release support windows, signing/attestations and distribution registries must be agreed before claiming long-term production support. No automatic publishing credentials are stored in this repository.
