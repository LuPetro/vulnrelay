# Security news

The optional **News** tab follows security reporting and advisories separately
from the asset-aware CVE alert engine. It reads publisher-provided RSS headlines,
publication dates and links from CISA Advisories, BleepingComputer and The
Hacker News. VulnRelay does not retrieve full articles or send your inventory to
these sources. RSS publishers receive the network request and can see your
server's IP address. Links open the original publisher's page.

## Set up news and notifications

1. Configure and test a connector under **Connectors** first if you want messages.
2. Open **News**, enable news collection and select one or more sources.
3. To receive individual newly discovered stories, enable notifications, choose
   the topics and existing connector destinations, and save. Notification
   destinations observe the connector's existing delivery schedule and rate limits.
4. The background monitor checks feeds at the configured synchronization interval
   (30 minutes by default). Saving settings requests a check on the next monitor
   cycle; allow time for the feeds to load. Status and last successful check are
   displayed per source. One unavailable feed does not stop the others.
5. Search headlines or CVE IDs, or filter by topic and headlines mentioning
   exploitation or zero-days. Follow a link for the full original report.

The first successful check of each feed stores the current headlines without
sending them. Subsequent newly observed items are queued once per source URL and
destination; retry and recovery use the normal persistent outbox. If a connector
is disabled or a news subscription changes, waiting items are revalidated before
delivery. As with other notifications, delivery is at least once: a failure
between external acceptance and the local acknowledgement can cause a duplicate.
Reports on the same event from different publishers are separate stories and may
produce separate messages. Feed outages, publication delays or missing RSS
entries can cause gaps; this is not an exhaustive worldwide news feed.

Categories and highlights are **simple headline keyword rules**, not verified
threat intelligence, a popularity ranking or proof that a product is affected.
A headline mentioning a zero-day is not itself proof of active exploitation.
Consult the linked source and official vendor advisories. The news subscription is
off by default and does not require AI. Current news messages contain the title,
source, publication date and link; this feature does not produce summaries or
scheduled news digests. Articles are stored locally without automatic expiry in
this version.
