"""Bundled, offline starter catalog; explicit identities, never inventory discovery."""

from typing import Literal
from urllib.parse import urlencode
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.matching import _identity
from vulnrelay.schemas import Asset

# IDs are stable public identifiers. Product names are NVD CPE identities, not
# search keywords. Blank vendor deliberately matches the product across vendors.
# This is a maintained starter selection, not a mirror of the CPE dictionary.
_PRODUCTS = [
    (
        "ubuntu",
        "Ubuntu",
        "Operating systems",
        "canonical",
        "ubuntu_linux",
        "Linux server and desktop",
    ),
    ("debian", "Debian", "Operating systems", "debian", "debian_linux", "Linux distribution"),
    (
        "rhel",
        "Red Hat Enterprise Linux",
        "Operating systems",
        "redhat",
        "enterprise_linux",
        "RHEL enterprise servers",
    ),
    (
        "linux",
        "Linux kernel",
        "Operating systems",
        "linux",
        "linux_kernel",
        "Kernel across Linux distributions",
    ),
    (
        "windows-server",
        "Windows Server 2022",
        "Operating systems",
        "microsoft",
        "windows_server_2022",
        "Microsoft server operating system",
    ),
    (
        "windows",
        "Windows 11",
        "Operating systems",
        "microsoft",
        "windows_11",
        "Microsoft desktop operating system",
    ),
    ("openssh", "OpenSSH", "Infrastructure", "openbsd", "openssh", "SSH remote access"),
    ("openssl", "OpenSSL", "Infrastructure", "openssl", "openssl", "TLS and cryptography library"),
    (
        "nginx",
        "NGINX",
        "Web & proxies",
        "",
        "nginx",
        "Web server and reverse proxy; includes renamed vendors",
    ),
    (
        "apache",
        "Apache HTTP Server",
        "Web & proxies",
        "apache",
        "http_server",
        "Apache web server / httpd",
    ),
    (
        "tomcat",
        "Apache Tomcat",
        "Web & proxies",
        "apache",
        "tomcat",
        "Java servlet application server",
    ),
    (
        "haproxy",
        "HAProxy",
        "Web & proxies",
        "haproxy",
        "haproxy",
        "Load balancer and reverse proxy",
    ),
    (
        "traefik",
        "Traefik",
        "Web & proxies",
        "traefik",
        "traefik",
        "Container ingress and reverse proxy",
    ),
    ("caddy", "Caddy", "Web & proxies", "caddyserver", "caddy", "HTTPS web server"),
    (
        "nodejs",
        "Node.js",
        "Languages & frameworks",
        "nodejs",
        "node.js",
        "JavaScript runtime / node",
    ),
    ("python", "Python", "Languages & frameworks", "python", "python", "CPython runtime"),
    ("php", "PHP", "Languages & frameworks", "php", "php", "PHP runtime"),
    (
        "java",
        "Oracle JDK",
        "Languages & frameworks",
        "oracle",
        "jdk",
        "Java Development Kit; not every Java distribution",
    ),
    (
        "django",
        "Django",
        "Languages & frameworks",
        "djangoproject",
        "django",
        "Python web framework",
    ),
    (
        "nextjs",
        "Next.js",
        "Languages & frameworks",
        "vercel",
        "next.js",
        "React application framework / next",
    ),
    (
        "postgresql",
        "PostgreSQL",
        "Data stores",
        "postgresql",
        "postgresql",
        "Relational database / postgres",
    ),
    ("mysql", "MySQL", "Data stores", "", "mysql", "Relational database; includes renamed vendors"),
    ("redis", "Redis", "Data stores", "redis", "redis", "In-memory data store and cache"),
    ("mongodb", "MongoDB", "Data stores", "mongodb", "mongodb", "Document database"),
    (
        "elasticsearch",
        "Elasticsearch",
        "Data stores",
        "elastic",
        "elasticsearch",
        "Search and analytics engine",
    ),
    ("sqlite", "SQLite", "Data stores", "sqlite", "sqlite", "Embedded SQL database"),
    (
        "docker",
        "Docker Engine",
        "Containers & cloud",
        "",
        "moby",
        "Moby engine; does not include Docker Desktop",
    ),
    (
        "containerd",
        "containerd",
        "Containers & cloud",
        "linuxfoundation",
        "containerd",
        "Container runtime",
    ),
    (
        "kubernetes",
        "Kubernetes",
        "Containers & cloud",
        "kubernetes",
        "kubernetes",
        "Container orchestration / k8s",
    ),
    ("helm", "Helm", "Containers & cloud", "helm", "helm", "Kubernetes package manager"),
    (
        "terraform",
        "Terraform",
        "Containers & cloud",
        "hashicorp",
        "terraform",
        "Infrastructure as code",
    ),
    ("vault", "Vault", "Infrastructure", "hashicorp", "vault", "Secrets management"),
    (
        "consul",
        "Consul",
        "Infrastructure",
        "hashicorp",
        "consul",
        "Service discovery and networking",
    ),
    ("grafana", "Grafana", "Observability", "grafana", "grafana", "Monitoring dashboards"),
    ("prometheus", "Prometheus", "Observability", "prometheus", "prometheus", "Metrics monitoring"),
    ("zabbix", "Zabbix", "Observability", "zabbix", "zabbix", "Infrastructure monitoring"),
    (
        "jenkins",
        "Jenkins",
        "Developer tools",
        "jenkins",
        "jenkins",
        "CI automation server; plugins need separate assets",
    ),
    ("gitlab", "GitLab", "Developer tools", "gitlab", "gitlab", "Self-hosted code and CI platform"),
    ("gitea", "Gitea", "Developer tools", "gitea", "gitea", "Self-hosted Git service"),
    ("git", "Git", "Developer tools", "git-scm", "git", "Distributed version control"),
    (
        "nextcloud",
        "Nextcloud Server",
        "Applications",
        "nextcloud",
        "nextcloud_server",
        "Self-hosted collaboration and files",
    ),
    (
        "wordpress",
        "WordPress",
        "Applications",
        "wordpress",
        "wordpress",
        "CMS core; plugins need separate assets",
    ),
    ("drupal", "Drupal", "Applications", "drupal", "drupal", "CMS core"),
    (
        "keycloak",
        "Keycloak",
        "Applications",
        "",
        "keycloak",
        "Identity and access management; includes renamed vendors",
    ),
    ("esxi", "VMware ESXi", "Infrastructure", "vmware", "esxi", "Virtualization hypervisor"),
    (
        "vcenter",
        "VMware vCenter Server",
        "Infrastructure",
        "vmware",
        "vcenter_server",
        "Virtualization management",
    ),
    (
        "fortios",
        "Fortinet FortiOS",
        "Network & security",
        "fortinet",
        "fortios",
        "FortiGate firewall operating system",
    ),
    (
        "ios-xe",
        "Cisco IOS XE",
        "Network & security",
        "cisco",
        "ios_xe",
        "Routing and switching operating system",
    ),
    (
        "pan-os",
        "Palo Alto PAN-OS",
        "Network & security",
        "paloaltonetworks",
        "pan-os",
        "Firewall operating system",
    ),
    (
        "sonicos",
        "SonicWall SonicOS",
        "Network & security",
        "sonicwall",
        "sonicos",
        "Firewall operating system",
    ),
]

PRODUCTS = {
    key: {
        "id": key,
        "name": name,
        "category": category,
        "description": description,
        "kind": "vendor_product" if vendor else "product",
        "vendor": vendor,
        "product": product,
        "source_url": "https://nvd.nist.gov/products/cpe/search/results?"
        + urlencode(
            {"keyword": f"{vendor} {product}".strip(), "status": "FINAL", "orderBy": "CPEURI"}
        ),
    }
    for key, name, category, vendor, product, description in _PRODUCTS
}

PACKS = [
    {
        "id": "linux-server",
        "name": "Linux essentials",
        "description": "A starting point for an Ubuntu server. Change the selection to match what you run.",
        "category": "Infrastructure",
        "products": ["ubuntu", "linux", "openssh", "openssl"],
    },
    {
        "id": "web-stack",
        "name": "Modern web app",
        "description": "A Node.js application with a proxy, database and cache.",
        "category": "Applications",
        "products": ["nginx", "nodejs", "nextjs", "postgresql", "redis"],
    },
    {
        "id": "python-stack",
        "name": "Python application",
        "description": "A Django service with PostgreSQL behind NGINX.",
        "category": "Applications",
        "products": ["python", "django", "postgresql", "nginx", "redis"],
    },
    {
        "id": "containers",
        "name": "Container platform",
        "description": "Common components of a Kubernetes platform. Select only those you use.",
        "category": "Containers & cloud",
        "products": ["linux", "containerd", "kubernetes", "helm", "traefik"],
    },
    {
        "id": "homelab",
        "name": "Self-hosted homelab",
        "description": "An example stack for personal services and file sharing.",
        "category": "Infrastructure",
        "products": ["debian", "openssh", "docker", "caddy", "nextcloud", "postgresql"],
    },
    {
        "id": "observability",
        "name": "Observability",
        "description": "Metrics, dashboards and their supporting data store.",
        "category": "Observability",
        "products": ["grafana", "prometheus", "elasticsearch"],
    },
    {
        "id": "devops",
        "name": "Delivery toolchain",
        "description": "Git, CI and infrastructure tooling for a development team.",
        "category": "Developer tools",
        "products": ["git", "gitlab", "jenkins", "terraform", "vault"],
    },
    {
        "id": "wordpress-stack",
        "name": "WordPress site",
        "description": "CMS core and a typical PHP/MySQL hosting stack. Plugins are separate.",
        "category": "Applications",
        "products": ["wordpress", "php", "mysql", "apache"],
    },
    {
        "id": "network",
        "name": "Network perimeter",
        "description": "A selection of common firewall and network platforms; remove vendors you do not run.",
        "category": "Network & security",
        "products": ["fortios", "ios-xe", "pan-os", "sonicos"],
    },
    {
        "id": "virtualization",
        "name": "VMware infrastructure",
        "description": "Hypervisor and management plane with a Windows server guest.",
        "category": "Infrastructure",
        "products": ["esxi", "vcenter", "windows-server"],
    },
]


class CatalogSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    products: list[str] = Field(min_length=1, max_length=100)
    group: str = Field(default="production", min_length=1, max_length=100)
    environment: str = Field(default="production", max_length=100)
    team: str = Field(default="", max_length=100)
    importance: Literal["low", "normal", "high", "critical"] = "normal"
    exposed: bool = False

    @field_validator("products")
    @classmethod
    def known_products(cls, value):
        if any(key not in PRODUCTS for key in value):
            raise ValueError("Unknown catalog product")
        return list(dict.fromkeys(value))

    @field_validator("group", "environment", "team")
    @classmethod
    def clean_context(cls, value, info):
        value = value.strip()
        if info.field_name == "group" and not value:
            raise ValueError("An asset group is required")
        return value


def catalog(query: str = "") -> dict:
    words = query.casefold().split()
    return {
        "version": 1,
        "products": [
            p
            for p in PRODUCTS.values()
            if all(
                word
                in " ".join(
                    str(p[k])
                    for k in ("id", "name", "category", "description", "vendor", "product")
                ).casefold()
                for word in words
            )
        ],
        "packs": PACKS,
    }


def identity(asset: Asset) -> tuple:
    """Names and policy settings do not create another copy of the same identity/context."""
    return (
        asset.kind,
        _identity(asset.vendor),
        _identity(asset.product),
        asset.version.strip(),
        asset.cpe,
        asset.keyword.casefold(),
        asset.group,
        asset.environment,
        asset.team,
    )


def import_selection(engine: Engine, selection: CatalogSelection, *, preview: bool = False) -> dict:
    candidates = [
        Asset(
            name=PRODUCTS[key]["name"],
            kind=PRODUCTS[key]["kind"],
            vendor=PRODUCTS[key]["vendor"],
            product=PRODUCTS[key]["product"],
            **selection.model_dump(exclude={"products"}),
        )
        for key in selection.products
    ]
    result: dict = {"created": [], "existing": [], "preview": preview}
    with engine.connect() as connection:
        # Serialize the read-and-insert operation, including simultaneous requests.
        # A second import must see the first one's assets before deciding to insert.
        if not preview:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            elif engine.dialect.name == "postgresql":
                connection.exec_driver_sql("LOCK TABLE assets IN SHARE ROW EXCLUSIVE MODE")
            else:
                raise ValueError("Unsupported database for catalog imports")
        existing = {}
        for row in connection.execute(text("SELECT id,document FROM assets ORDER BY id")):
            try:
                asset = Asset.model_validate_json(row.document)
            except ValueError:
                continue  # Invalid legacy entries must not stop unrelated valid imports.
            existing.setdefault(identity(asset), {"id": row.id, **asset.model_dump()})
        for asset in candidates:
            key = identity(asset)
            if key in existing:
                result["existing"].append(existing[key])
                continue
            document = {"id": str(uuid4()), **asset.model_dump()}
            result["created"].append(document)
            existing[key] = document
            if not preview:
                connection.execute(
                    text("INSERT INTO assets (id,document) VALUES (:id,:document)"),
                    {"id": document["id"], "document": asset.model_dump_json()},
                )
        if not preview:
            connection.commit()
    return result
