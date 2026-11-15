# Troubleshooting

- **No data:** wait for the first source cycle, inspect Overview source errors, then run `vulnrelay doctor` or `docker compose logs monitor`. First NVD bootstrap is seven modified days, not all CVE history.
- **NVD synchronization failed:** updated versions report a safe reason in Overview/Settings, monitor logs and the manual sync CLI. Run `docker compose exec monitor vulnrelay check-nvd` for one read-only request with a 10-second network timeout, or append `--json` for scripting. This works alongside the monitor, does not change database state, does not retry and exits nonzero on failure. It reports whether an API key is configured without printing it. A successful probe does not verify date-window pagination, normalization or database writes. Network timeouts apply to individual network operations, not a strict total wall-clock deadline.
- **NVD timeout / connection failure:** check outbound HTTPS, DNS, TLS and proxy configuration; retry later. A timeout does not establish whether the provider, network or a proxy caused the delay. No API key is required by VulnRelay; absence alone does not explain an error.
- **NVD HTTP 403 / 429:** a 403 means the request was denied; check the key if configured and network/request restrictions without assuming one cause. A 429 means the request was rate limited; wait rather than repeatedly invoking sync. HTTP 5xx indicates an upstream error. No provider response body, response header, raw exception or token is included in diagnostics.
- **NVD invalid response / checkpoint:** an invalid response can mean malformed JSON or an incomplete page; retry later. An invalid/future saved checkpoint needs a server-clock/state review. Do not delete checkpoints or the database to hide an error. Failed synchronization retains previous records, checkpoint and last-success time; a subsequent successful sync clears the error. A connectivity probe does not clear or overwrite it. Older generic errors become specific only after another failed synchronization.
- **No messages:** confirm an enabled asset, rule and connector, inspect rule test evidence, and verify the worker is running. Missing scores remain unknown and cannot satisfy numeric thresholds. A queued test does not send until a worker or `vulnrelay deliver` processes it.
- **Cancelled alert:** the current rule, asset or vulnerability no longer qualifies. Read the recorded reason. Re-evaluate after correcting the configuration; cancelled messages are not sent or manually retried.
- **Inventory version conflicts with the version in the CPE:** correct the inventory version or CPE so they describe the same asset. An empty optional version field uses the CPE's version. Conflicting legacy asset documents are skipped and need correction; monitoring other valid assets continues.
- **Failed Telegram delivery:** check the token variable, group/chat ID, bot membership and permission to send. Change `.env`, recreate both containers using `docker compose up -d --force-recreate`, then queue a fresh test. Terminal failures are not retried indefinitely. Do not post logs with tokens.
- **Duplicate alert after crash:** external delivery is at least once; a crash between accepted send and local acknowledgement may repeat it. Separate assets and material changes also create separately attributed events.
- **Database schema error:** run `vulnrelay init` or restart Compose. Back up persistent data before upgrades. Configuration and history are not stored in the container's disposable filesystem.
- **Monitor already running:** one monitor/synchronizer owns a per-database lock. Stop the other process gracefully before a manual sync. A crashed Unix process automatically releases its lock.
- **API 401:** enter the configured API bearer token in Settings. It is kept in browser memory only.
- **API 403:** mutations require the custom request header and matching Origin. Use the provided frontend or supply the documented headers in scripts.
- **UI missing in native installation:** run `npm ci && npm run build` inside `frontend/`, then restart the API from the repository root. Docker builds the frontend automatically.
- **Inspect or stop:** `docker compose ps`, `docker compose logs monitor`, `docker compose stop`. Do not use `down -v` unless you intentionally want to delete the database volume.

After upgrading, wait for the next scheduled source cycle (30 minutes by default). To synchronize immediately instead, pause only this installation's monitor, run one synchronization, then start the monitor again even if sync failed:

```sh
docker compose stop monitor
docker compose exec vulnrelay vulnrelay sync
docker compose start monitor
```

The paused worker does not process notifications during the manual synchronization. Keep the API container running. The source error describes the last failed sync; check its last-success time separately. Never post `.env`, API keys or raw provider responses when requesting support.
