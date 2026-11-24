# Package monitoring with OSV.dev

The optional OSV integration checks user-declared package names and **one exact
version** against the public OSV.dev API. It supports npm, PyPI, Go, Maven,
crates.io and NuGet package identities. Enter the package using the syntax of
its ecosystem (for example `django`, `@scope/name`, `example.org/module`, or
`group:artifact`). You can also resolve a supported, unqualified package URL
with an exact version into these fields. Version ranges, wildcards, qualified
PURLs, lockfile/SBOM import and automatic discovery are not supported yet.

## Setup

1. In **Assets → Add asset**, choose **package**, its ecosystem, its exact
   installed version and a descriptive local name/group. Existing product and
   keyword assets continue to work independently. Maintain the declared version
   when your actual installation changes.
   Alternatively, paste an unqualified PURL such as `pkg:npm/next@15.1.0` or
   `pkg:npm/%40angular/core@17.1.0` into **Package URL**, choose **Use package
   URL**, review the resulting fields and save the asset. Previewing the URL
   does not create an asset or send it to OSV. The stored configuration contains
   the resolved identity fields, not the original URL. To review and import
   several PURLs together, see [package list import](package-import.md).
2. In your server's private `.env`, set `VULNRELAY_OSV_ENABLED=true`. Recreate
   both containers with `docker compose up -d --force-recreate` so they read the
   updated environment. No OSV API key is needed. This sends the declared
   **package ecosystem, name and exact version** to OSV.dev. Local asset names,
   groups, rules and connector credentials are not sent.
3. Keep the monitor running. It checks up to 20 package assets per normal sync
   interval, prioritizing the assets checked least recently. The Assets page
   shows each package's last successful check or a safe error; Overview shows
   aggregate source health. Failed or incomplete responses leave the last complete
   snapshot intact and are retried on later cycles.
4. Make sure an enabled notification rule can match these records. For example,
   add a condition `confidence equals confirmed` for the package asset/group.
   An OSV-only CVE can have no numeric CVSS, EPSS or KEV assessment; a rule that
   requires an unavailable score will correctly not match it. OSV does not
   overwrite NVD or OpenCVE scores. Verify an alert with your installed inventory
   and the linked source advisory.

OSV's result means the public advisory matches the **declared package and
version**. VulnRelay cannot verify that your declared inventory actually matches
what is installed or that the application is exploitable in your environment.
The alert names OSV, provides a direct advisory link and explains the match.
Repeated checks of unchanged findings do not enqueue duplicate alerts. Changed
or withdrawn findings are handled on a subsequent successful query, and queued
alerts are rechecked before delivery.

The first implementation correlates OSV records with a CVE identifier or CVE
alias; advisories without a CVE alias are currently omitted. It does not claim
complete coverage of every package or vulnerability. A previous finding may be
stale during an OSV outage; consult its last successful check and source. Package
identities are normalized only where OSV's documented ecosystem rules permit it.

PURL input is deliberately limited to the package ecosystems listed above and
their `npm`, `pypi`, `golang`, `maven`, `cargo` and `nuget` types. It requires an
explicit version and rejects qualifiers, subpaths, ambiguous namespaces,
version ranges and common moving tags such as `latest`. For Go, use the actual
module path; a PURL alone cannot establish whether a path names a module rather
than a package within it. Unsupported PURLs are not silently simplified. See
the [Package URL specification](https://github.com/package-url/purl-spec) and
the [Go type definition](https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/golang-definition.md).

The same import works without the GUI: `vulnrelay assets add dependency.json`
accepts a file such as:

```json
{
  "name": "Application dependency",
  "kind": "package",
  "purl": "pkg:npm/next@15.1.0",
  "group": "app"
}
```

You can still enter the ecosystem, package and version directly. If those
fields are also provided alongside a PURL, they must agree with its resolved
identity. Changing the resolved identity clears any previous OSV snapshot, so
an old version's findings cannot be reused for a new version.

For a manual headless check, stop the monitor for its database lock, run a batch,
and start it again:

```sh
docker compose stop monitor
docker compose exec vulnrelay vulnrelay sync-osv
docker compose start monitor
```

The command prints how many assets were checked or failed and how many remain;
repeat it for additional batches. The monitor subsequently evaluates the saved
findings and sends matching queued alerts. Automated tests mock OSV and do not
send real package inventory. API reference: [OSV query](https://google.github.io/osv.dev/post-v1-query/)
and [OSV schema](https://ossf.github.io/osv-schema/).
