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
    (
        "mariadb",
        "MariaDB",
        "Data stores",
        "mariadb",
        "mariadb",
        "Relational database server; independent of MySQL",
    ),
    (
        "memcached",
        "Memcached",
        "Data stores",
        "memcached",
        "memcached",
        "Distributed in-memory cache",
    ),
    ("minio", "MinIO", "Data stores", "minio", "minio", "S3-compatible object storage"),
    (
        "rabbitmq",
        "RabbitMQ Server",
        "Data stores",
        "broadcom",
        "rabbitmq_server",
        "Message broker; current Broadcom identity, legacy names are separate",
    ),
    (
        "openvpn",
        "OpenVPN Community",
        "Network & security",
        "openvpn",
        "openvpn",
        "Community VPN software; Access Server is a separate product",
    ),
    (
        "pfsense-ce",
        "pfSense CE",
        "Network & security",
        "netgate",
        "pfsense_ce",
        "Community firewall; current CE identity, legacy pfsense is separate",
    ),
    (
        "pfsense-plus",
        "pfSense Plus",
        "Network & security",
        "netgate",
        "pfsense_plus",
        "Commercial firewall edition; separate from pfSense CE",
    ),
    (
        "opnsense",
        "OPNsense",
        "Network & security",
        "opnsense",
        "opnsense",
        "Open source firewall and routing platform",
    ),
    (
        "routeros",
        "MikroTik RouterOS",
        "Network & security",
        "mikrotik",
        "routeros",
        "Router and wireless networking operating system",
    ),
    (
        "unifi-network",
        "UniFi Network Application",
        "Network & security",
        "ui",
        "unifi_network_application",
        "Ubiquiti network controller; not all UniFi device firmware",
    ),
    (
        "adguard-home",
        "AdGuard Home",
        "Network & security",
        "adguard",
        "adguard_home",
        "Self-hosted DNS filtering server",
    ),
    (
        "pi-hole",
        "Pi-hole Core",
        "Network & security",
        "pi-hole",
        "pi-hole",
        "DNS filtering core; FTL and web interface identities are separate",
    ),
    (
        "samba",
        "Samba",
        "Infrastructure",
        "samba",
        "samba",
        "SMB file sharing and Active Directory services",
    ),
    (
        "proxmox-backup",
        "Proxmox Backup Server",
        "Backup & storage",
        "proxmox",
        "backup_server",
        "Virtual machine and container backup service; not Proxmox VE",
    ),
    (
        "syncthing",
        "Syncthing",
        "Backup & storage",
        "syncthing",
        "syncthing",
        "Peer-to-peer file synchronization; not a backup guarantee",
    ),
    (
        "jellyfin",
        "Jellyfin",
        "Applications",
        "jellyfin",
        "jellyfin",
        "Self-hosted media server; plugins need separate assets",
    ),
    (
        "immich",
        "Immich",
        "Applications",
        "futo",
        "immich",
        "Self-hosted photo and video management",
    ),
    (
        "home-assistant",
        "Home Assistant",
        "Applications",
        "home-assistant",
        "home-assistant",
        "Home automation core; add-ons and integrations are separate",
    ),
    (
        "mattermost",
        "Mattermost Server",
        "Applications",
        "mattermost",
        "mattermost_server",
        "Self-hosted team messaging; separate from desktop clients",
    ),
    (
        "rocketchat",
        "Rocket.Chat",
        "Applications",
        "rocket.chat",
        "rocket.chat",
        "Self-hosted team chat platform",
    ),
    (
        "roundcube",
        "Roundcube Webmail",
        "Applications",
        "roundcube",
        "webmail",
        "Browser-based email client; not your mail server",
    ),
    (
        "vaultwarden",
        "Vaultwarden",
        "Identity & access",
        "dani-garcia",
        "vaultwarden",
        "Unofficial Bitwarden-compatible password server; not Bitwarden Server",
    ),
    (
        "authentik",
        "authentik",
        "Identity & access",
        "goauthentik",
        "authentik",
        "Identity provider and single sign-on",
    ),
    (
        "authelia",
        "Authelia",
        "Identity & access",
        "authelia",
        "authelia",
        "Authentication and authorization portal",
    ),
    (
        "ansible",
        "Ansible",
        "Developer tools",
        "redhat",
        "ansible",
        "Automation engine; collections and Automation Platform are separate",
    ),
    (
        "spring-framework",
        "Spring Framework",
        "Languages & frameworks",
        "vmware",
        "spring_framework",
        "Java application framework; Spring Boot and Security are separate",
    ),
    (
        "express",
        "Express",
        "Languages & frameworks",
        "openjsf",
        "express",
        "Node.js web framework / npm express; legacy vendor identities are separate",
    ),
    (
        "fastapi",
        "FastAPI",
        "Languages & frameworks",
        "tiangolo",
        "fastapi",
        "Python API framework / PyPI fastapi; dependencies are separate",
    ),
    (
        "flask",
        "Flask",
        "Languages & frameworks",
        "palletsprojects",
        "flask",
        "Python WSGI framework / PyPI flask; extensions are separate",
    ),
    (
        "laravel",
        "Laravel Framework",
        "Languages & frameworks",
        "laravel",
        "framework",
        "PHP web framework / Composer laravel/framework",
    ),
    (
        "vite",
        "Vite",
        "Developer tools",
        "vitejs",
        "vite",
        "JavaScript build tooling / npm vite; development-server advisories",
    ),
    (
        "log4j",
        "Apache Log4j",
        "Libraries & dependencies",
        "apache",
        "log4j",
        "Java logging library; inspect the affected component in each advisory",
    ),
    (
        "lodash",
        "Lodash",
        "Libraries & dependencies",
        "lodash",
        "lodash",
        "JavaScript utility library / npm lodash",
    ),
    (
        "axios",
        "Axios",
        "Libraries & dependencies",
        "axios",
        "axios",
        "HTTP client library / npm axios",
    ),
    (
        "requests",
        "Requests",
        "Libraries & dependencies",
        "python",
        "requests",
        "Python HTTP client / PyPI requests; current NVD vendor identity",
    ),
    (
        "urllib3",
        "urllib3",
        "Libraries & dependencies",
        "python",
        "urllib3",
        "Python HTTP library / PyPI urllib3",
    ),
    (
        "pyyaml",
        "PyYAML",
        "Libraries & dependencies",
        "pyyaml",
        "pyyaml",
        "Python YAML parser / PyPI pyyaml",
    ),
]

# Reviewed NVD records: see docs/catalog-sources.md. These prove product identity,
# not installed-version applicability or complete package/advisory coverage.
_IDENTITY_SOURCES = {
    "mariadb": "https://nvd.nist.gov/vuln/detail/CVE-2026-44168",
    "memcached": "https://nvd.nist.gov/vuln/detail/CVE-2020-22570",
    "minio": "https://nvd.nist.gov/products/cpe/detail/1362917",
    "rabbitmq": "https://nvd.nist.gov/products/cpe/detail/CAE3183B-DE75-4B49-B84F-ED0359FD9585",
    "openvpn": "https://nvd.nist.gov/vuln/detail/CVE-2024-28882",
    "pfsense-ce": "https://nvd.nist.gov/vuln/detail/CVE-2024-54780",
    "pfsense-plus": "https://nvd.nist.gov/vuln/detail/CVE-2024-54780",
    "opnsense": "https://nvd.nist.gov/vuln/detail/CVE-2023-44275",
    "routeros": "https://nvd.nist.gov/vuln/detail/CVE-2023-32154",
    "unifi-network": "https://nvd.nist.gov/vuln/detail/CVE-2026-54405",
    "adguard-home": "https://nvd.nist.gov/vuln/detail/CVE-2021-27935",
    "pi-hole": "https://nvd.nist.gov/vuln/detail/CVE-2024-34361",
    "samba": "https://nvd.nist.gov/vuln/detail/CVE-2018-14628",
    "proxmox-backup": "https://nvd.nist.gov/products/cpe/detail/11b7078d-4daf-430a-971c-6e8c34d2f3ca",
    "syncthing": "https://nvd.nist.gov/vuln/detail/CVE-2022-46165",
    "jellyfin": "https://nvd.nist.gov/vuln/detail/CVE-2023-27161",
    "immich": "https://nvd.nist.gov/vuln/detail/CVE-2026-23896",
    "home-assistant": "https://nvd.nist.gov/products/cpe/detail/26470246-2d6c-41f7-a4eb-a2bffa10df84",
    "mattermost": "https://nvd.nist.gov/products/cpe/detail/cc50bdb1-011c-4751-8d19-a43b27e58a8d",
    "rocketchat": "https://nvd.nist.gov/vuln/detail/CVE-2018-13878",
    "roundcube": "https://nvd.nist.gov/products/cpe/detail/ab8baf79-0d3d-4fa0-bb4b-4feaf9c1b18a",
    "vaultwarden": "https://nvd.nist.gov/vuln/detail/CVE-2026-26012",
    "authentik": "https://nvd.nist.gov/products/cpe/detail/1886224",
    "authelia": "https://nvd.nist.gov/vuln/detail/CVE-2021-32637",
    "ansible": "https://nvd.nist.gov/vuln/detail/CVE-2016-3096",
    "spring-framework": "https://nvd.nist.gov/vuln/detail/CVE-2026-47889",
    "express": "https://nvd.nist.gov/products/cpe/detail/dd703bd4-a544-4ed0-a03b-0daeb0a511e5",
    "fastapi": "https://nvd.nist.gov/products/cpe/detail/651c3d53-e199-4aff-bd4c-a00b7fab1fdb",
    "flask": "https://nvd.nist.gov/vuln/detail/CVE-2023-30861",
    "laravel": "https://nvd.nist.gov/vuln/detail/CVE-2025-27515",
    "vite": "https://nvd.nist.gov/products/cpe/detail/588b0b84-29a8-46ad-af78-9e5cccf04a4c",
    "log4j": "https://nvd.nist.gov/products/cpe/detail/f6128969-81cb-40a1-b7dc-d66481147087",
    "lodash": "https://nvd.nist.gov/products/cpe/detail/0b7abcbf-af48-450a-b1b5-fb5650ade0a1",
    "axios": "https://nvd.nist.gov/products/cpe/detail/8B564ABB-E560-46FF-AD88-416EC34A5596",
    "requests": "https://nvd.nist.gov/products/cpe/detail/18693de3-904b-4fb0-88dd-65d571c50797",
    "urllib3": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
    "pyyaml": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
}

PRODUCTS = {
    key: {
        "id": key,
        "name": name,
        "category": category,
        "description": description,
        "kind": "vendor_product" if vendor else "product",
        "vendor": vendor,
        "product": product,
        "source_url": _IDENTITY_SOURCES.get(key)
        or "https://nvd.nist.gov/products/cpe/search/results?"
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
    {
        "id": "identity-access",
        "name": "Identity & access",
        "description": "Common sign-on and password services. Pick the providers you actually run.",
        "category": "Identity & access",
        "products": ["keycloak", "authentik", "authelia", "vaultwarden", "postgresql"],
    },
    {
        "id": "home-services",
        "name": "Home services",
        "description": "Media, photos and home automation. Add-ons and plugins need their own assets.",
        "category": "Applications",
        "products": ["home-assistant", "jellyfin", "immich", "postgresql", "redis"],
    },
    {
        "id": "collaboration",
        "name": "Team collaboration",
        "description": "Files, chat and webmail examples. Remove alternative services you do not host.",
        "category": "Applications",
        "products": ["nextcloud", "mattermost", "rocketchat", "roundcube", "postgresql"],
    },
    {
        "id": "open-network",
        "name": "Small network & DNS",
        "description": "Firewall, controller, VPN and DNS options. Select your firewall and DNS service; remove alternatives.",
        "category": "Network & security",
        "products": [
            "opnsense",
            "pfsense-ce",
            "routeros",
            "unifi-network",
            "openvpn",
            "adguard-home",
            "pi-hole",
        ],
    },
    {
        "id": "python-api",
        "name": "Python APIs & libraries",
        "description": "Choose FastAPI or Flask and the libraries your application uses. This does not inspect a requirements file.",
        "category": "Languages & frameworks",
        "products": ["python", "fastapi", "flask", "requests", "urllib3", "pyyaml", "postgresql"],
    },
    {
        "id": "javascript-app",
        "name": "JavaScript application",
        "description": "Runtime, frameworks, build tools and common npm libraries. Select only your direct or known transitive components.",
        "category": "Languages & frameworks",
        "products": ["nodejs", "express", "nextjs", "vite", "axios", "lodash"],
    },
    {
        "id": "java-service",
        "name": "Java service",
        "description": "An Oracle JDK and Spring/Tomcat example with Log4j. Use your actual Java distribution and components.",
        "category": "Languages & frameworks",
        "products": ["java", "spring-framework", "tomcat", "log4j", "postgresql"],
    },
    {
        "id": "data-services",
        "name": "Data services",
        "description": "Database, cache, object storage and messaging options. Choose the services you operate.",
        "category": "Data stores",
        "products": ["postgresql", "mariadb", "redis", "memcached", "minio", "rabbitmq"],
    },
    {
        "id": "files-backups",
        "name": "Files & backups",
        "description": "File sharing, synchronization, object storage and Proxmox Backup Server. Synchronization alone is not a backup.",
        "category": "Backup & storage",
        "products": ["samba", "syncthing", "minio", "proxmox-backup"],
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
