# OpenCVE Knowledge Base

VulnRelay can enrich CVEs from the public [OpenCVE Knowledge Base](https://github.com/opencve/opencve-kb). OpenCVE combines information from multiple upstream providers and documents its [record format and aggregation rules](https://docs.opencve.io/concepts/kb/). This integration reads those JSON records directly over HTTPS. No OpenCVE account, API token, additional database or full repository clone is required.

## Manual lookup

Open a CVE under **Vulnerabilities** and click **Load OpenCVE details**. The detail view shows the separate assessment, original provider labels, source link and last check time. An absent record is reported explicitly. A lookup itself does not enqueue a notification; a running monitor can subsequently evaluate the enriched data against enabled rules.

CLI equivalents:

```sh
vulnrelay lookup-opencve CVE-2021-44228
vulnrelay cve CVE-2021-44228
vulnrelay sync-opencve
```

Docker users can prefix these commands with `docker compose exec vulnrelay`. `lookup-opencve` accepts a single valid CVE ID and returns JSON with `found` and `record`. `sync-opencve` refreshes one bounded batch of already known local CVEs; it does not discover or import the entire OpenCVE catalog. Stop the monitor before running a manual batch refresh because both use the database monitor lock. Individual lookups can run while monitoring continues.

The API is `POST /api/sources/opencve/{CVE_ID}/lookup`. It requires the normal mutation header (`X-VulnRelay-Request: 1`) and bearer token when configured. Cached assessments are included in `GET /api/vulnerabilities/{CVE_ID}`; listing and reading cached data require no upstream request.

## Optional background enrichment

Set these values in `.env`:

```dotenv
VULNRELAY_OPENCVE_ENABLED=true
VULNRELAY_OPENCVE_BATCH_SIZE=25
```

Recreate both containers with `docker compose up -d --build --force-recreate`. Background enrichment is disabled by default; manual lookups remain available. Turning background enrichment off retains previously cached assessments and they remain usable by rules.

When enabled, OpenCVE is checked at the configured source interval (30 minutes by default). Each run considers at most 25 CVEs by default (configurable from 1 to 100). Candidates come from locally stored NVD/KEV records and successful manual OpenCVE lookups. Records checked in the past 24 hours, including absent records, are skipped. Unchecked records are considered first, starting with descending CVE IDs, followed by older checks. This is bounded enrichment, not a complete historical synchronization or a real-time feed. A large local inventory takes multiple batches to enrich.

## Data selection and matching

- Original OpenCVE JSON, its normalized assessment, ETag, provider modification time and local check/retrieval times are stored separately in `opencve_records` (migration 0006).
- An existing numeric NVD CVSS remains primary, including a legitimate zero. OpenCVE CVSS is used only when NVD has no score. Conflicting scores stay inspectable in the separate assessment; the selected score's source is identified in the API, UI and notifications.
- Existing NVD/CISA descriptions remain primary; OpenCVE can fill missing text. FIRST EPSS and direct CISA KEV status are not overwritten by aggregated OpenCVE metrics.
- OpenCVE vendor/product identities can produce potential matches. Flat merged CPE lists lack applicability conditions, so even an identical CPE never produces a confirmed version match through this strategy. NVD rejected status still excludes a CVE. OpenCVE-only records have unknown record status.
- A CVE shared by NVD, KEV and OpenCVE remains one local CVE identity. Existing rule and event deduplication applies; material data changes can still trigger configured re-notifications.

## Reliability and privacy

Requests use fixed OpenCVE KB URLs on `raw.githubusercontent.com`; record links point to its GitHub repository. Requests contain a public CVE ID, not asset names, groups, tags or credentials. No custom upstream URL is accepted. Redirects are refused, responses are bounded to 4 MiB, timeouts are applied and transient HTTP/transport failures have bounded retry/backoff. Rate-limit, transport and server failures stop the batch rather than continuing across all candidate CVEs. Long Retry-After cooldowns stop immediate retries and defer the persistent monitor schedule, keeping delivery independent of the wait.

ETags support conditional requests. A 404 is cached as a checked miss so missing records cannot starve other candidates. Invalid, older, unavailable or missing responses do not delete an existing valid assessment. `checked_at` means a check occurred; it does not mean the provider's underlying CVE information changed. Errors are generic, recorded in source health and isolated from other sources and delivery. Raw records add storage and are included in database backups; the upstream dataset is not bundled with VulnRelay's source repository.

This adapter uses OpenCVE's public KB format. OpenCVE REST API v2 tokens, organizations, project subscriptions and authenticated self-hosted API synchronization are separate future integrations. The documented initial scope is the same account-free data source available to OpenCVE instances.
