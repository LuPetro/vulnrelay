# Docker quick start

This guide creates a **new** local alpha installation using SQLite. If you
already have an instance, use [backup and upgrade](backup-and-upgrade.md)
instead. To run a second instance on the same server, use the
[separate test installation](server-test-installation.md).

## 1. Requirements

- A Linux host, Git, Docker Engine and Docker Compose **2.24 or later**. The
  user running Compose needs working access to the Docker daemon.
- Outbound HTTPS for the public sources and any notification services used.
- Enough disk space for the image, database and backups. The first build can
  take several minutes and consume substantial memory on a small server.
- Access to the GitHub repository. Until it is public, use an authorized SSH
  key or a GitHub token when prompted over HTTPS; a GitHub account password is
  not a Git authentication token. Do not put credentials in the clone URL.

Check `docker --version`, `docker compose version` and that `docker info` can
connect to the daemon. A separate NVD API key is optional; without one,
upstream rate limits can make the initial synchronization slower.

## 2. Clone and start

These commands target the current `development` branch. `main` is the default
branch but does not yet contain the complete alpha. Run them in a directory
where a new `vulnrelay` folder can be created:

```sh
git clone --branch development https://github.com/LuPetro/vulnrelay.git
cd vulnrelay
cp .env.example .env
chmod 600 .env
docker compose up -d --build --wait --wait-timeout 180
docker compose ps
```

The command builds the application image and starts an API/UI container and a
monitor container. Their database and scheduling state use a named Docker
volume. Health checks do not mean every upstream source has already finished
synchronizing. If your first build or start fails, inspect
`docker compose logs --tail 100 vulnrelay monitor` after reviewing the output
for private data.

The example `.env` has no connector credentials and AI and OSV are disabled.
Never overwrite an existing `.env`; it can contain your credentials. After
editing it, recreate both containers with `docker compose up -d --force-recreate --wait --wait-timeout 180`.
A container restart alone does not reload changed
environment variables.

## 3. Open the interface

On the Docker host, open **http://localhost:8080**. Compose publishes this port
only on `127.0.0.1`. For a remote server, run the following on your **own
computer**, substituting the SSH user and host, and keep the tunnel open:

```sh
ssh -N -L 8080:127.0.0.1:8080 USER@SERVER
```

Then open **http://localhost:8080** on that computer. If you choose a different
`VULNRELAY_PORT`, adjust both port numbers accordingly. The API's optional token
does not make direct Internet exposure supported; do not open the port publicly.

## 4. Configure your first destination and rule

1. Under **Catalog** or **Assets**, add an actual technology to a small test
   group. A catalog product match is potential, not proof of an affected version.
2. Follow [Telegram setup](telegram.md), or choose another connector from the
   [documentation index](README.md). Put secrets in `.env`, recreate the
   containers, and enter the **environment variable name** in the UI.
3. Under **Connectors**, queue a test and verify it arrives in the intended
   channel. Test messages use the worker, queue, pacing and any delivery hours.
4. Under **Notification rules**, select the test asset/group and destination.
   Rules default to enabled: uncheck **Rule enabled** before saving, then test
   against stored CVEs before enabling it. An enabled broad rule can immediately
   match existing records; it is not limited to future CVEs.
5. Check **Overview** and delivery history. For an end-to-end check of an actual
   CVE, duplicate protection and restart recovery, follow the
   [acceptance checklist](acceptance.md).

No NVD or AI credential is needed for this flow. AI can incur provider charges
if explicitly configured and enabled; see [AI settings](ai.md). To monitor
exact package versions, opt in to [OSV](osv.md).

## 5. Day-to-day checks

```sh
docker compose ps
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
docker compose exec monitor vulnrelay check-nvd
```

`engine-health` checks the worker heartbeat, not destination delivery or
source freshness. `check-nvd` performs one read-only connectivity probe; it
does not prove a full NVD synchronization succeeded. Source errors, last
success and the next attempt appear in Overview. See [troubleshooting](troubleshooting.md).

To pause the instance, use `docker compose stop`; resume with
`docker compose up -d --wait`. Do not run `docker compose down -v` if you want
to keep its volume. Create and test [backups](backup-and-upgrade.md) before an
update or relying on the stored inventory.
