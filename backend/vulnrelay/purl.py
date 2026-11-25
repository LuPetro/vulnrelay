"""Convert a conservative subset of package URLs to OSV package identities."""

import re
from urllib.parse import unquote

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "nuget": "NuGet",
}


def _decode(part: str) -> str:
    if not part or re.search(r"%(?![0-9a-fA-F]{2})", part):
        raise ValueError("Invalid package URL encoding")
    try:
        value = unquote(part, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("Invalid package URL encoding") from None
    if not value or value in (".", "..") or any(char in value for char in "/?#"):
        raise ValueError("Invalid package URL component")
    return value


def package_identity(purl: str) -> dict[str, str]:
    """Resolve supported, unqualified PURLs; reject ambiguous identities.

    Qualifiers and subpaths can change what a package denotes and are not
    discarded. The caller validates the resulting exact version separately.
    """
    if (
        not isinstance(purl, str)
        or not 1 <= len(purl) <= 1000
        or not purl.startswith("pkg:")
        or "?" in purl
        or "#" in purl
        or purl.count("@") != 1
    ):
        raise ValueError("Package URL must have a supported type and one exact version")
    path, raw_version = purl[4:].split("@")
    parts = path.split("/")
    if len(parts) < 2 or parts[0] not in ECOSYSTEMS:
        raise ValueError("Unsupported package URL type")
    ecosystem = parts[0]
    names = [_decode(part) for part in parts[1:]]
    version = _decode(raw_version)
    if version.casefold() in {"latest", "stable", "nightly", "next", "master", "main", "head"}:
        raise ValueError("Package URL must contain an exact version, not a moving tag")
    simple_name = r"[A-Za-z0-9][A-Za-z0-9._-]*"
    if ecosystem == "npm" and len(names) == 2:
        if not re.fullmatch(r"@[A-Za-z0-9][A-Za-z0-9._-]*", names[0]):
            raise ValueError("Invalid npm scope")
        if not re.fullmatch(simple_name, names[1]):
            raise ValueError("Invalid npm package")
        package = "/".join(names)
    elif ecosystem == "golang" and len(names) >= 2:
        if not all(re.fullmatch(simple_name, part) for part in names):
            raise ValueError("Invalid Go module identity")
        package = "/".join(names)
    elif ecosystem == "maven" and len(names) == 2:
        if not all(re.fullmatch(simple_name, part) for part in names):
            raise ValueError("Invalid Maven package identity")
        package = ":".join(names)
    elif ecosystem in ("npm", "pypi", "cargo", "nuget") and len(names) == 1:
        if not re.fullmatch(simple_name, names[0]):
            raise ValueError("Invalid package identity")
        package = names[0]
    else:
        raise ValueError("Unsupported package URL namespace")
    return {"ecosystem": ECOSYSTEMS[ecosystem], "package": package, "version": version}
