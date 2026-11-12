# Security policy

This project is alpha; no supported production release exists yet. Keep it bound to localhost. Optional bearer-token protection applies to `/api`; this is not a complete remote-access security model. Host validation and cross-origin mutation protection reduce local browser attack surface, and source/AI content must be treated as untrusted.

Never commit connector credentials. Connector configuration references environment variables, with optional native `.env` fallback. Keep `.env` and the persistent data volume private: they contain secrets or infrastructure inventory. Delivery error records omit raw provider exception strings. Notifications leave the local machine and contain configured asset names and vulnerability information.

For a suspected vulnerability, use GitHub private vulnerability reporting if available on this repository. Do not include credentials or exploit details in public issues. If private reporting is unavailable, contact the repository owner through a private channel before disclosing details. No security review or certification is implied.
