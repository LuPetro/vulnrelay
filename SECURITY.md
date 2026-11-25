# Security policy

VulnRelay is alpha software; no supported production release exists yet. No
independent security review or certification is implied. The supported default
is localhost access. Optional bearer-token protection applies to `/api`; it is
not a complete remote-access security model. Use an SSH tunnel for a remote
host rather than exposing the application directly to the Internet.

## Reporting a vulnerability

Please do not publish credentials, exploit details or affected private
infrastructure in an issue or pull request. Use the repository's
[private vulnerability reporting page](https://github.com/LuPetro/vulnrelay/security/advisories)
if the owner has enabled that feature. Its availability has not yet been
verified. If it is unavailable, contact the repository owner through a
verified private channel before sending details. Do not use a guessed email
address. Before public release, the owner must establish and verify at least
one confidential reporting route; see [GitHub settings](docs/github-settings.md).
The optional private reporting form lives in `.github/VULNERABILITY_REPORT.yml`;
it takes effect on the default branch after the repository feature is enabled.
Adding the form does not enable private reporting by itself.

## Protecting an installation

- Never commit connector credentials. Connector configuration references
  server environment variables, with an optional native `.env` fallback.
- Keep `.env`, the persistent data volume, exports and backups private. They
  may contain credentials or infrastructure inventory. Review ownership,
  access and storage permissions; the application does not encrypt the whole
  database or backups for you.
- Notifications leave the host and may contain asset names, matching evidence
  and vulnerability information. Choose destinations and retention
  accordingly. Delivery error records omit raw provider exception strings.
- Opt-in OSV requests disclose declared package names and exact versions to
  OSV. Optional AI summaries send a public CVE identifier and its public
  description to the configured provider after a rule match; connection tests
  are real requests and can incur charges. Review [OSV](docs/osv.md) and
  [AI privacy and controls](docs/ai.md).
- Treat source and AI content as untrusted. Enable access to private outbound
  endpoints only for trusted services; see the relevant connector guides.

Configuration requests are bounded before JSON parsing. Native SQLite files
created by the application and online backup files use private file modes;
existing files and host backup storage still need operator review. `/ready`
checks the installed database revision, while worker health uses a separate
recent delivery-thread heartbeat. These operational checks do not certify
upstream data freshness or security.

CI uses read-only repository permissions, pinned actions and no production
credentials. Scheduled dependency audits and offline secret checks are
configured; repository-level secret scanning, push protection and private
vulnerability reporting are separate GitHub settings and are not asserted to
be enabled. A passing automated scan is not a complete security assessment.
