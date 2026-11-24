# Import a package URL list

The package list import adds several user-declared dependencies at once. It
accepts up to 100 supported package URLs (PURLs), each with a concrete version.
It does not discover installed packages or parse lockfiles and SBOM documents.

1. Open **Assets → Import package list** and paste one PURL per line, for
   example:

   ```text
   pkg:npm/next@15.1.0
   pkg:npm/%40angular/core@17.1.0
   pkg:pypi/django@5.1.0
   ```

2. Choose a group and, optionally, an environment, team, importance and
   Internet exposure. These settings apply to newly created assets.
3. Choose **Review package list**. The preview displays new and existing or
   repeated identities; expand the latter to inspect disabled entries. If a
   URL is invalid, the numbered entry is reported and nothing is written.
4. Review existing notification rules before choosing **Import packages**.
   Broad enabled rules can match newly created assets on the next monitoring
   cycle. Change any input or context to require a new review.

Import is an atomic transaction. Repeated imports and concurrent imports reuse
an existing asset for the same normalized ecosystem/package, exact version
string, group, environment and team. Existing names, tags, importance,
exposure and enabled/disabled state are preserved; a disabled asset is not
re-enabled. Different groups, teams, environments or version strings are
treated as separate assets. Equivalent but differently spelled versions are
not assumed to be the same. Existing duplicates are not merged or deleted.

Preview and import run locally and do not contact OSV. When OSV monitoring is
enabled, the monitor subsequently sends each enabled asset's declared package
identity and version to OSV.dev. It cannot verify what is actually installed.
Only CVE-linked OSV advisories are currently correlated. The accepted PURL
types, exact-version requirement, unsupported qualifiers/subpaths and Go
module caveat are described in [OSV setup](osv.md).

## CLI and API

The CLI accepts a JSON selection file such as:

```json
{
  "purls": ["pkg:npm/next@15.1.0", "pkg:pypi/django@5.1.0"],
  "group": "application",
  "environment": "staging",
  "team": "app",
  "importance": "normal",
  "exposed": false
}
```

Run `vulnrelay packages import packages.json --preview` and then, after
reviewing the result, `vulnrelay packages import packages.json`. With Docker,
copy the file into the container first, for example
`docker compose cp packages.json vulnrelay:/tmp/packages.json`, and run the
commands with `docker compose exec vulnrelay` and `/tmp/packages.json`.

The equivalent API endpoints are `POST /api/packages/preview` and
`POST /api/packages/import`. They use the existing local authentication and
mutation-header requirements. Preview is not a reservation: the import checks
for duplicates again under a database lock, so concurrent changes cannot
silently overwrite existing assets.
