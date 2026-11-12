# Backup, restore and upgrade

## Consistent online SQLite backup

Use the application backup command rather than copying a database file while its WAL is active:

```sh
vulnrelay backup ./vulnrelay-backup.db
# Compose installation: create inside the persistent volume, then copy it out.
docker compose exec vulnrelay vulnrelay backup /app/data/pre-upgrade.db
docker compose cp vulnrelay:/app/data/pre-upgrade.db ./vulnrelay-backup.db
```

Choose a new destination each time; the command never overwrites a file. The backup uses SQLite's online backup API, includes committed WAL data, validates integrity and creates a private file. It contains asset inventory, rule/configuration data and delivery state. `.env` secrets are not included; back up those separately using a secure mechanism. Keep backups private, preferably encrypted and outside the host. Do not commit them. PostgreSQL needs its own supported backup tooling and is not handled by this command.

## Restore rehearsal

Rehearse on a fresh, disposable installation before relying on a backup. Stop its API and monitor, restore to an empty destination and preserve file ownership/permissions (container user 10001). Point a native test environment to a fresh copy using VULNRELAY_DATABASE_URL, run `vulnrelay init` and `vulnrelay doctor`, and check inventory/rules/history. Do not start monitoring against an old restored queue until you have reviewed it: restoring earlier delivery state can re-send previously delivered messages. External Telegram delivery is at least once.

For a real recovery, stop both services first and keep the current data volume as a fallback. Do not overwrite a running database or mix a backup with unrelated old -wal/-shm files. Restore into a fresh database/volume and switch the installation to it after verification. Restore automation and external backup retention are not implemented, so review the procedure before production use.

## Upgrade

1. Read the changelog and compatibility notes; create and validate a new backup plus a protected copy of `.env`.
2. Stop the monitoring worker and API cleanly. Do not run an old binary concurrently with a migration.
3. Build/use the reviewed candidate, run migrations (`vulnrelay init`), then start API and monitor.
4. Check `/ready`, `vulnrelay doctor`, worker health, source errors and delivery history.
5. Validate a controlled test message and asset rule. Keep the pre-upgrade backup until the result is accepted.

Schema downgrade tests run on disposable CI databases. They are not a promise that every downgrade preserves every user's data. A rollback may require restoring a compatible backup rather than downgrading a live database.
