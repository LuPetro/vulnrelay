"""Deterministic CPE identity and explicit keyword matching, with conservative applicability."""

import re

from vulnrelay.schemas import Asset


def split_cpe(value: str) -> list[str]:
    parts = re.split(r"(?<!\\):", value)
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        raise ValueError("A CPE 2.3 formatted string with 11 components is required")
    return parts


def cpe_version_consistent(cpe: str, version: str) -> bool:
    """An explicit inventory version must agree with an explicit CPE version."""
    component = split_cpe(cpe)[5]
    return (
        not version.strip()
        or component == "*"
        or version.strip() == re.sub(r"\\(.)", r"\1", component)
    )


def _identity(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value).casefold().replace(" ", "_")


def _leaves(nodes, constrained=False):
    for node in nodes:
        restricted = constrained or node.get("operator", "OR") != "OR" or node.get("negate", False)
        for item in node.get("cpeMatch", []):
            if item.get("vulnerable") is True:
                yield item, restricted
        yield from _leaves(node.get("nodes", []) + node.get("children", []), restricted)


def match(asset: Asset, vulnerability: dict) -> dict | None:
    if not asset.enabled or vulnerability.get("status", "").casefold() == "rejected":
        return None
    if asset.kind == "package":
        from vulnrelay.osv import identity

        for item in vulnerability.get("osv", []):
            if (item["ecosystem"], item["package"], item["version"]) == identity(asset):
                return {
                    "method": "osv_package_version",
                    "confidence": "confirmed",
                    "evidence": {
                        "osv_id": item["osv_id"],
                        "ecosystem": asset.ecosystem,
                        "package": asset.package,
                        "version": asset.version,
                        "modified": item["record"].get("modified"),
                    },
                    "explanation": "OSV reports that the declared package and exact version are affected; verify the installed inventory.",
                }
        return None
    if asset.kind == "cpe" and not cpe_version_consistent(asset.cpe, asset.version):
        # Also protect callers holding an old/unchecked model after an upgrade.
        return None
    if asset.kind == "keyword":
        if re.search(
            r"(?<!\w)" + re.escape(asset.keyword) + r"(?!\w)",
            vulnerability.get("description") or "",
            re.IGNORECASE,
        ):
            return {
                "method": "keyword",
                "confidence": "potential",
                "evidence": asset.keyword,
                "explanation": "Explicit keyword appears in the description; installed version applicability is unverified.",
            }
        return None
    entries = list(_leaves(vulnerability.get("nvd", {}).get("configurations", [])))
    for item, constrained in entries:
        try:
            parts = split_cpe(item["criteria"])
        except (KeyError, ValueError):
            continue
        vendor, product = parts[3:5]
        if asset.kind == "cpe":
            wanted = split_cpe(asset.cpe)
            # Wildcards and target platform attributes are deliberately not guessed.
            identity = all(
                _identity(a) == _identity(b) for a, b in zip(wanted[2:5], parts[2:5], strict=True)
            )
        else:
            identity = (not asset.vendor or _identity(asset.vendor) == _identity(vendor)) and (
                not asset.product or _identity(asset.product) == _identity(product)
            )
        if not identity:
            continue
        confidence = "unknown" if asset.version or asset.kind == "cpe" else "potential"
        # A literal whole CPE in an unconstrained OR branch can confirm applicability.
        exact = asset.kind == "cpe" and asset.cpe == item["criteria"] and not constrained
        no_ranges = not any(key.startswith(("versionStart", "versionEnd")) for key in item)
        if (
            exact
            and no_ranges
            and all(part not in ("*", "-") for part in split_cpe(asset.cpe)[2:6])
        ):
            confidence = "confirmed"
        return {
            "method": "cpe_exact" if confidence == "confirmed" else "vendor_product",
            "confidence": confidence,
            "evidence": item,
            "explanation": "Exact vulnerable CPE in an unconstrained OR branch."
            if confidence == "confirmed"
            else "Product identity matches; version and environment applicability need verification.",
        }
    # CISA identities provide additional evidence without asserting version applicability.
    kev = vulnerability.get("kev_record") or {}
    if (
        asset.kind != "cpe"
        and kev
        and (not asset.vendor or _identity(asset.vendor) == _identity(kev.get("vendorProject", "")))
        and (not asset.product or _identity(asset.product) == _identity(kev.get("product", "")))
    ):
        return {
            "method": "cisa_identity",
            "confidence": "unknown" if asset.version else "potential",
            "evidence": {"vendor": kev.get("vendorProject"), "product": kev.get("product")},
            "explanation": "CISA catalog product identity matches; installed version applicability is unverified.",
        }
    # Flat OpenCVE CPEs lack applicability logic and can only provide identity evidence.
    opencve = vulnerability.get("opencve") or {}
    wanted_vendor, wanted_product = asset.vendor, asset.product
    if asset.kind == "cpe":
        parts = split_cpe(asset.cpe)
        wanted_vendor, wanted_product = parts[3:5]
    identities = list(opencve.get("vendors", []))
    for cpe in opencve.get("cpes", []):
        try:
            parts = split_cpe(cpe)
        except ValueError:
            continue
        identities.append({"vendor": parts[3], "product": parts[4]})
    for identity in identities:
        if (not wanted_vendor or _identity(wanted_vendor) == _identity(identity["vendor"])) and (
            not wanted_product
            or _identity(wanted_product) == _identity(identity.get("product") or "")
        ):
            return {
                "method": "opencve_identity",
                "confidence": "unknown" if asset.version or asset.kind == "cpe" else "potential",
                "evidence": {**identity, "source": "OpenCVE", "source_url": opencve["source_url"]},
                "explanation": "OpenCVE product identity matches; merged CPEs do not establish installed-version applicability.",
            }
    return None
