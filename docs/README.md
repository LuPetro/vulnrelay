# Documentation

VulnRelay is an alpha self-hosted vulnerability notification engine. Start with
the installation guide, then verify a real alert before relying on it. The
[repository README](../README.md) gives a short overview and current limitations.

## Get started

| I want to… | Guide |
| --- | --- |
| Install and configure a fresh instance | [Docker quick start](quickstart.md) |
| Eine Installation auf Deutsch durchführen | [Schnellstart und Serverzugriff](schnellstart.md) |
| Run a separate test instance beside another installation | [Separate server test installation](server-test-installation.md) |
| Update an existing test instance | [Update und Test der neuen Funktionen](update-und-test.md) |
| Verify an actual CVE reaches Telegram | [Acceptance checklist](acceptance.md) · [Deutsch](first-test.md) |
| Run without Docker or use the command line | [Native installation and CLI](cli.md) |

## Configure and operate

| Topic | Guide |
| --- | --- |
| Products and environment packs | [Catalog](catalog.md) · [Catalog source evidence](catalog-sources.md) |
| Asset matching and notification rules | [Configuration](configuration.md) |
| Package/version monitoring | [OSV](osv.md) · [Package URL list import](package-import.md) |
| Destination setup | [Telegram](telegram.md) · [Discord and Slack](webhook-connectors.md) · [Email](email.md) · [ntfy and Gotify](push-connectors.md) · [Generic webhook](generic-webhook.md) |
| Delivery windows, retries and backlog | [Delivery hours](connector-schedules.md) · [Queue](delivery-queue.md) |
| Scheduled summaries | [Daily and weekly reports](reports.md) |
| Security news and alerts | [News subscriptions](news.md) |
| Optional intelligence | [OpenCVE](opencve.md) · [AI summaries](ai.md) |
| Backup and troubleshooting | [Backup, restore and upgrade](backup-and-upgrade.md) · [Troubleshooting](troubleshooting.md) |

The interactive API reference is available at `/docs` on the running local
instance. Requests that change data require `X-VulnRelay-Request: 1`, a
same-origin request when an Origin header is supplied, and the API bearer token
if configured. See [security](../SECURITY.md) before considering any access
outside localhost.

## Contribute and maintain

- [Architecture and data flow](architecture.md)
- [Development and verification](development.md)
- [Contributing](../CONTRIBUTING.md), [code of conduct](../CODE_OF_CONDUCT.md)
  and [governance](../GOVERNANCE.md)
- [License and attribution](licensing.md) and [third-party notices](../THIRD_PARTY_NOTICES.md)
- [Roadmap](../PROJECT_PLAN.md), [changelog](../CHANGELOG.md) and
  [release checklist](releasing.md)
- [GitHub administration](github-settings.md)
- [GitHub-Einstellungen auf Deutsch](github-einrichten.md)
- [Brand and UI behavior](brand.md) and [frontend design](frontend-design.md)

Screenshots in `docs/images/` come from the project's automated browser tests
with synthetic data. The monitor is intentionally stopped in those test
fixtures; screenshots are illustrations of the interface, not production health
or proof of delivery. Refresh them from a reviewed CI artifact when the UI
changes and do not use a real installation or private inventory.
