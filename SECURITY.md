# Security policy

This project is alpha; no supported production release exists yet. Keep it bound to localhost. Optional bearer-token protection applies to `/api`; this is not a complete remote-access security model. Host validation and cross-origin mutation protection reduce local browser attack surface, and source/AI content must be treated as untrusted.

Never commit connector credentials. Connector configuration references environment variables, with optional native `.env` fallback. Keep `.env` and the persistent data volume private: they contain secrets or infrastructure inventory. Delivery error records omit raw provider exception strings. Notifications leave the local machine and contain configured asset names and vulnerability information.

For a suspected vulnerability, use GitHub private vulnerability reporting if available on this repository. Do not include credentials or exploit details in public issues. If private reporting is unavailable, contact the repository owner through a private channel before disclosing details. No security review or certification is implied.

Configuration requests are bounded before JSON parsing. Native SQLite files created by the application and online backup files use private file modes; existing files and host backup storage still need operator review. `/ready` checks the installed database revision, while worker health uses a separate recent delivery-thread heartbeat. These operational checks do not certify upstream data freshness or security.

CI uses read-only repository permissions, immutable action pins and no production credentials. Scheduled dependency audits and offline secret checks are configured; repository-level secret scanning, push protection and private vulnerability reporting are separate GitHub settings and are not asserted to be enabled. See [docs/github-settings.md](docs/github-settings.md). Audit findings must be fixed or explicitly reviewed; passing an automated audit is not a complete security assessment.
