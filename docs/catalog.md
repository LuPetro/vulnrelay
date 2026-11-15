# Technology catalog and environment packs

The **Catalog** page offers 50 bundled technologies and ten starter packs: Linux essentials, modern web app, Python application, container platform, homelab, observability, delivery toolchain, WordPress site, network perimeter and VMware infrastructure. It works offline and requires no external catalog account.

1. Search a technology or select a category. **Matching identity** shows the exact product/vendor used and links to the NVD CPE dictionary.
2. Alternatively open **Environment packs**. A pack shows its components before selection. Remove anything you do not run and add other technologies individually.
3. Choose an asset group and environment. Team, importance and Internet exposure are optional context.
4. **Review selection** shows new and already-present assets without writing anything. A context change requires a new review.
5. **Add assets** saves the selection in one transaction. The Assets page can search names, products, groups and environments. Existing manual add/edit remains available.

On smaller screens, **Review N selected** takes you directly to your selection and environment settings. It does not import anything.

Packs are examples, not automatic inventory discovery or a claim that a stack is complete. No software is installed on your server. Catalog items use explicit product identities, never automatic fuzzy matching. A product match is potential; it does not confirm that an installed version is vulnerable. Add installed versions by editing the resulting assets, keeping the existing version-matching limitations in mind. CMS plugins, Java distributions and Docker Desktop need their own appropriate entries. Product-only entries intentionally cover vendor renames and disclose their broader scope.

Existing enabled rules may apply to new assets immediately, particularly rules selecting all assets or an existing group. Review your rules before importing a large selection. Catalog imports do not create rules or connectors, change existing settings, or directly enqueue alerts.

## Duplicate handling

Repeated IDs in one selection are collapsed. A repeated or overlapping import reuses existing assets with the same matching strategy, vendor/product identity, version, CPE/keyword, group, environment and team. This includes matching manually created entries. Names, importance, exposure, tags and enabled state of existing entries are preserved; importing a disabled asset does not re-enable it. Different environments, teams, versions or matching strategies remain separate inventory entries. Existing duplicate manual entries are not automatically merged or deleted.

Imports serialize the read-and-insert transaction, so simultaneous imports cannot create copies of the same catalog identity/context. A failed insert rolls back the entire selection. This is separate from CVE ingestion deduplication and notification deduplication. Different matching assets or rules can legitimately produce distinct alerts for the same CVE.

## CLI

Use these commands inside the installed environment, or prefix them with `docker compose exec vulnrelay`:

```sh
vulnrelay catalog list --query postgres
vulnrelay catalog pack linux-server --group servers --environment production --preview
vulnrelay catalog pack linux-server --group servers --environment production
```

For an individually selected list, save a file such as:

```json
{"products":["nginx","postgresql","redis"],"group":"web","environment":"staging","team":"app","importance":"high","exposed":false}
```

Then run `vulnrelay catalog add selection.json --preview` and `vulnrelay catalog add selection.json`. With Docker, first copy your file into the container using `docker compose cp selection.json vulnrelay:/tmp/selection.json`, then use `/tmp/selection.json` as the CLI path.

The API exposes `GET /api/catalog?q=...`, `POST /api/catalog/preview` and `POST /api/catalog/import`. Writes require the existing mutation header and configured bearer authentication.

## Freshness and maintenance

The bundled starter catalog changes with application updates; it is not a live mirror of the [NVD CPE dictionary](https://nvd.nist.gov/products/cpe). Matching data and product identities may be incomplete upstream. Catalog maintainers must review identities against NVD and preserve stable catalog IDs. CI validates every entry, pack membership, import behavior and conservative match confidence without requiring live network access.

CVE records continue to synchronize independently. NVD and CISA default to 30-minute polling, EPSS to daily refresh, with persistent checkpoints and visible source errors. Newer NVD records update existing CVE IDs; older responses cannot overwrite newer NVD data. This does not guarantee instant or complete upstream coverage. The initial NVD window is the last seven modified days, plus historical CISA KEV records; adding a catalog asset does not trigger a full NVD historical backfill. Optional OpenCVE enriches known CVEs and is not a full catalog discovery source.

Unchanged alerts for the same CVE/asset/rule/destination are deduplicated. Relevant changes can cause another alert if enabled. Delivery remains at least once: a crash between Telegram acceptance and the local delivery acknowledgement can repeat a message.

## Update and test an existing Docker installation

Run from your own installation folder. Keep its `.env`, project/image names and persistent data volume. This increment needs no new schema migration and preserves existing asset IDs, rules, connectors and notification history.

First create a new backup and copy it outside the container (keep it private):

```sh
cd ~/vulnrelay-test
backup_name="pre-catalog-$(date -u +%Y%m%dT%H%M%SZ).db"
docker compose exec vulnrelay vulnrelay backup "/app/data/$backup_name"
docker compose cp "vulnrelay:/app/data/$backup_name" "./$backup_name"
chmod 600 "./$backup_name"
git pull --ff-only origin development
```

If backup or pull fails, resolve that before continuing. On a small VPS, stop only this installation before building to free its memory; source checkpoints and data remain saved:

```sh
docker compose stop
docker compose build
docker compose up -d --wait --wait-timeout 180
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
```

Run each step only after the previous one succeeds. Refresh the browser (hard refresh if needed). Open **Catalog**, select a small pack, remove one component, choose a new test group, and review before importing. Repeat the same selection/context: the preview should say zero new assets. Check that manual asset creation, your rules and the existing Telegram connector still work. Review existing broad rules before importing. Never use `down -v` for an update.
