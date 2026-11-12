# Assets and rules

The UI and CLI use the same validated configuration. `vulnrelay assets add file.json` adds an asset, `update ID file.json` replaces it, `list` prints its ID, and `delete ID` removes it. Connectors and rules offer the same CRUD commands. Examples are under `examples/`.

Supported asset kinds are vendor, product, vendor_product, cpe and keyword. Asset groups are labels stored on assets. Environment, team, importance, Internet exposure and tags provide context. Version strings are retained as inventory information; they do not imply automatic version-range validation. Vendor/product matching uses explicit CPE identities or CISA identities, not description fuzziness. Case and spaces versus underscores are normalized for identities. Explicit keyword matching uses word boundaries.

Rules choose asset IDs or group labels; empty selectors include all assets. Supported fields: cvss, severity, epss, percentile, kev, group, exposed, importance, confidence, vendor, product, keyword (description), tags. Metrics use gte/lte/eq and numeric values; kev/exposed use eq with booleans. Text uses eq, contains, or in with a list of strings. Group kinds are all, any and not. Rule depth and condition counts are bounded. A NOT of unknown remains unknown. Only true results are eligible for notification.

Rules may be tested while disabled. Enqueueing excludes disabled rules and disabled destinations. Deleting a connector leaves existing delivery history and makes queued deliveries fail visibly; it does not silently reroute them. Changing an entry's ID creates a distinct identity for deduplication purposes.

The initial implementation supports immediate compact and detailed formats. Digests, independent priority scoring and inventory import/export are planned. `/api/evaluate` and `vulnrelay rules test ID` show matching and condition evidence without sending alerts. `vulnrelay evaluate --enqueue` persists eligible alerts. `vulnrelay monitor` does this automatically.
