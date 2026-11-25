# Release checklist

VulnRelay is an alpha, not a supported stable release. The repository is
currently private and its default `main` branch does not yet contain the
current `development` work. A public **alpha** can be useful before every
roadmap feature is complete, provided its scope and limitations are clear.
Publication, a merge to the default branch, tags and releases require the
owner's explicit authorization.

## Before opening the repository as an alpha

- [x] The owner decided to continue with the VulnRelay name after being informed
  that [another security product](https://vulnrelay.app/en/) uses it. No
  trademark or domain availability determination is implied by that decision.
- [ ] Review the full contents of all Git branches, tags and commit history,
  plus issue and pull-request content, Actions logs and artifacts, images and
  screenshots. Look for credentials, private inventory, personal data and
  internal infrastructure details. A clean current tree and automated scans
  do not establish that the history is safe. An automated review on
  2026-11-25 found no identified real credentials but did find old internal
  workspace details; image/video contents were not visually reviewed. See
  `STATE.md` for scope and decide how to handle the historical details.
  Rotate exposed credentials and agree on remediation before publication.
- [ ] Review [GitHub's visibility-change consequences](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility):
  public visibility exposes repository content and Actions history/logs, and
  public push rulesets have different behavior. Check settings again after an
  approved change; do not assume protections carry over unchanged.
- [ ] Establish and verify a confidential security-reporting route. The
  [private reporting feature](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
  is a separate repository setting, not something `SECURITY.md` enables.
- [x] Include the unchanged Apache-2.0 license, project attribution and
  third-party notices in the source tree and distributions. Maintainers must
  review new dependencies and notices as they are added.
- [ ] Confirm a maintainer and practical contribution/support expectations.
- [ ] Review the current development work and draft PR, require green CI and
  Security checks on the intended commit, and arrange appropriate branch
  protections. Files in `development` do not update the default branch.
- [ ] Perform a clean installation and the
  [real-alert acceptance checklist](acceptance.md). Record what was actually
  tested, and retain explicit alpha limitations for anything still unverified.

## Before claiming a supported production v1

- [ ] Have someone else follow the installation and upgrade instructions on a
  clean host. Verify a real matching CVE alert, duplicate behavior, restarts,
  source outages and recovery with operator-controlled test destinations.
- [ ] Exercise a backup and restore on a separate instance, run a longer
  monitoring/queue soak test, and document operational limits and recovery.
- [ ] Complete a security and threat review, including dependencies,
  credentials, outbound integrations and the supported localhost/SSH access
  model. Define supported versions, response expectations and upgrade policy.
- [ ] Validate the providers and platforms advertised as supported. Keep
  unsupported features, source gaps and unverified version applicability
  clearly documented; a mock provider test is not live-service acceptance.

## Prepare an authorized release candidate

1. Update `backend/pyproject.toml` and `frontend/package.json` together.
   Python `0.1.0a0` and frontend `0.1.0-alpha.0` express the same prerelease.
   Run `python scripts/check_release.py` and keep the root and packaged Apache
   licenses identical.
2. Review dependency locks, audit findings, `CHANGELOG.md`, compatibility
   notes, attribution, license notices and the security policy. Document any
   explicit maintainer decisions; do not silently suppress findings.
3. Require green CI and Security checks on the candidate commit. The manually
   dispatched Release candidate workflow validates and builds the Python
   wheel/sdist and frontend bundle, with checksums and SBOMs as workflow
   artifacts. Artifact visibility follows repository permissions. The workflow
   does not publish a package, image or GitHub release.
4. Install the wheel in a clean Python environment and test the Compose
   candidate. Rehearse restore from a backup to a fresh database before
   upgrading an existing installation.
5. Only after owner approval, tag the reviewed commit and publish the validated
   artifacts and release notes using separately authorized credentials. Do
   not replace an already-published tag or artifact; release a new version.

See [GitHub administration](github-settings.md),
[development and verification](development.md) and the [roadmap](../PROJECT_PLAN.md).
