# Assets and rules

Use the [technology catalog and environment packs](catalog.md) to select common products without typing their matching identities. The catalog shares the same asset model and leaves manual creation/editing available.

The UI and CLI use the same validated configuration. `vulnrelay assets add file.json` adds an asset, `update ID file.json` replaces it, `list` prints its ID, and `delete ID` removes it. Connectors and rules offer the same CRUD commands. Examples are under `examples/`.

Supported asset kinds are `vendor`, `product`, `vendor_product`, `cpe`,
`keyword` and `package`. Asset groups are labels stored on assets. Environment,
team, importance, Internet exposure and tags provide context. Vendor/product
matching uses explicit CPE identities or CISA identities, not description
fuzziness. Case and spaces versus underscores are normalized for identities.
Explicit keyword matching uses word boundaries.

Package assets declare an ecosystem, package name and **one exact version**.
Optional OSV queries cover npm, PyPI, Go, Maven, crates.io and NuGet and
currently include only results with CVE identifiers or aliases. The OSV source
can report that your declared package/version matches an advisory; it cannot
verify what is installed. Supported unqualified PURLs can be resolved into
package fields individually or imported as a list. See [OSV](osv.md) and
[package list import](package-import.md).

Version strings on other asset types are retained as inventory information and
do not imply general version-range validation. Product and keyword matches are
potential; unverified applicability is unknown. A confirmed source match is not
proof that the actual host is exposed or exploitable.

For CPE assets, a separately supplied installed version must agree with an explicit CPE version. Conflicts are rejected on create/update. A wildcard CPE version remains unverified even when the inventory version is supplied. Invalid legacy asset documents are skipped with a warning so other assets continue monitoring; edit them to correct the conflict before relying on their alerts.

Rules choose asset IDs or group labels; empty selectors include all assets.
Supported fields: `cvss`, `severity`, `epss`, `percentile`, `kev`, `group`,
`exposed`, `importance`, `confidence`, `vendor`, `product`, `ecosystem`,
`package`, `keyword` (description) and `tags`. Metrics use `gte`/`lte`/`eq`
and numeric values; `kev`/`exposed` use `eq` with booleans. Text uses `eq`,
`contains`, or `in` with a list of strings. Group kinds are `all`, `any` and
`not`. Rule depth and condition counts are bounded. A NOT of unknown remains
unknown. Only true results are eligible for notification.

Rules may be tested while disabled. Enqueueing excludes disabled rules and disabled destinations. Before every delivery attempt, including retries and expired-claim recovery, alerts are checked against the current rule, asset, destination selection and stored vulnerability. Ineligible alerts become `cancelled` with a visible reason, without contacting the destination. Eligible alerts use current matching evidence, data and message format. Test messages require an enabled connector but no asset/rule. An HTTP request already in flight cannot be recalled by disabling a rule.

Cancelled alerts do not have a manual Retry action. If their rule/asset becomes eligible again, normal evaluation can requeue the existing event without losing deduplication for sent messages. Deleting a connector leaves existing delivery history and makes queued deliveries fail visibly; it does not silently reroute them. Changing an entry's ID creates a distinct identity for deduplication purposes.

Immediate alerts support compact and detailed formats. Separate daily and
weekly [reports](reports.md) are available; independent priority scoring and
general inventory JSON/YAML import/export remain planned. `/api/evaluate` and
`vulnrelay rules test ID` show matching and condition evidence without sending
alerts. `vulnrelay evaluate --enqueue` persists eligible alerts. The monitor
does this automatically.
