# Troubleshooting

- **No data:** wait for the first source cycle, inspect Overview source errors, then run `vulnrelay doctor` or `docker compose logs monitor`. First NVD bootstrap is seven modified days, not all CVE history.
- **No messages:** confirm an enabled asset, rule and connector, inspect rule test evidence, and verify the worker is running. Missing scores remain unknown and cannot satisfy numeric thresholds. A queued test does not send until a worker or `vulnrelay deliver` processes it.
- **Failed Telegram delivery:** check the token variable, group/chat ID, bot membership and permission to send. Change `.env`, restart the services, then queue a fresh test. Terminal failures are not retried indefinitely. Do not post logs with tokens.
- **Duplicate alert after crash:** external delivery is at least once; a crash between accepted send and local acknowledgement may repeat it. Separate assets and material changes also create separately attributed events.
- **Database schema error:** run `vulnrelay init` or restart Compose. Back up persistent data before upgrades. Configuration and history are not stored in the container's disposable filesystem.
- **Monitor already running:** one monitor/synchronizer owns a per-database lock. Stop the other process gracefully before a manual sync. A crashed Unix process automatically releases its lock.
- **API 401:** enter the configured API bearer token in Settings. It is kept in browser memory only.
- **API 403:** mutations require the custom request header and matching Origin. Use the provided frontend or supply the documented headers in scripts.
- **UI missing in native installation:** run `npm ci && npm run build` inside `frontend/`, then restart the API from the repository root. Docker builds the frontend automatically.
- **Inspect or stop:** `docker compose ps`, `docker compose logs monitor`, `docker compose stop`. Do not use `down -v` unless you intentionally want to delete the database volume.
