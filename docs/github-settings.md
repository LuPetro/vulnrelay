# GitHub administration

These are repository settings, not settings applied by committing YAML. The
repository is public and `main` is the default branch. Development changes
reach `main` through reviewed pull requests; changing files on `development`
alone does not update the public default branch. GitHub reports that `main`
is protected, but the precise protection settings have not been verified by
the connected integration.

1. Protect the default branch against force pushes and deletion; require pull
   requests and the tested CI contexts. Require resolved review conversations.
   Configure an approving review and code-owner review where practical; a
   sole owner needs a documented review exception rather than an impossible
   approval requirement. Check organization rulesets as well as branch rules.
2. Consider requiring `backend (3.12)`, `backend (3.13)`, `frontend`,
   `browser`, `container` and security `audit`. Verify actual check names in a
   completed run and ensure required checks can run on fork PRs. PR workflows
   use read-only repository permissions, not `pull_request_target`.
3. Keep workflow-token permissions minimal, avoid production credentials in
   CI, and review the pinned Actions and proposed Dependabot updates.
4. When available for the account and repository, enable secret-scanning
   alerts/push protection, dependency alerts and private vulnerability
   reporting. The committed audit workflows do not imply these settings are
   enabled. Do not enable paid products or change billing without approval.
5. Verify the confidential reporting flow as an outside contributor. The
   public advisories page displays **Report a vulnerability**; an actual
   submission has not been tested. If private reporting is unavailable, the
   maintainer must provide a verified private contact; do not invent one.
6. Review **all** branches, tags and history as well as PRs, issues, Actions
   logs and artifacts, and screenshots. Remove or remediate private content
   responsibly, rotate any exposed credentials and check third-party
   notices. Local secret checks do not certify the complete history as safe.
   GitHub explains the
   [visibility-change consequences](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility),
   including public Actions history/logs and changed push-ruleset behavior.
7. Keep releases manual. The release-candidate workflow builds artifacts
   without publishing packages, images or releases. Their visibility follows
   repository permissions. Review and explicitly approve the final release.

See the full [release checklist](releasing.md) for owner decisions and
acceptance criteria. Recheck protections and access after any owner-approved
visibility change; account permissions and feature availability can vary.
For step-by-step owner instructions in German, see
[GitHub für die Veröffentlichung einrichten](github-einrichten.md).
