"""Validated, portable configuration. Secrets are environment references only."""

from typing import Annotated, Any, Literal, Union
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True


class Asset(Document):
    kind: Literal["vendor", "product", "vendor_product", "cpe", "keyword", "package"]
    vendor: str = Field(default="", max_length=200)
    product: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=100)
    cpe: str = Field(default="", max_length=1000)
    keyword: str = Field(default="", max_length=200)
    package: str = Field(default="", max_length=200)
    ecosystem: str = Field(default="", max_length=80)
    group: str = Field(default="default", min_length=1, max_length=100)
    environment: str = Field(default="", max_length=100)
    team: str = Field(default="", max_length=100)
    importance: Literal["low", "normal", "high", "critical"] = "normal"
    exposed: bool = False
    tags: list[str] = Field(default_factory=list, max_length=30)

    @model_validator(mode="after")
    def validate_identity(self):
        required = {
            "vendor": (self.vendor,),
            "product": (self.product,),
            "vendor_product": (self.vendor, self.product),
            "cpe": (self.cpe,),
            "keyword": (self.keyword,),
            "package": (self.package, self.ecosystem, self.version),
        }[self.kind]
        if not all(item.strip() for item in required):
            raise ValueError("The selected asset type needs its identity fields")
        if self.kind == "cpe":
            from vulnrelay.matching import cpe_version_consistent

            if not cpe_version_consistent(self.cpe, self.version):
                raise PydanticCustomError(
                    "cpe_version_conflict",
                    "Inventory version conflicts with the version in the CPE",
                )
        if self.kind == "package":
            import re

            if self.ecosystem not in ("npm", "PyPI", "Go", "Maven", "crates.io", "NuGet"):
                raise ValueError("Unsupported package ecosystem")
            if not re.fullmatch(r"[A-Za-z0-9@_./:+-]{1,200}", self.package):
                raise ValueError("Invalid package name")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!~-]{0,99}", self.version):
                raise ValueError("Enter one exact installed version, not a range")
            if re.search(r"(?:^|\.)[xX](?:\.|$)", self.version):
                raise ValueError("Enter one exact installed version, not a range")
        if any(len(tag) > 100 for tag in self.tags):
            raise ValueError("Tags must not exceed 100 characters")
        return self


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["condition"] = "condition"
    field: Literal[
        "cvss",
        "severity",
        "epss",
        "percentile",
        "kev",
        "group",
        "exposed",
        "importance",
        "confidence",
        "vendor",
        "product",
        "ecosystem",
        "package",
        "keyword",
        "tags",
    ]
    op: Literal["gte", "lte", "eq", "in", "contains"]
    value: Any

    @model_validator(mode="after")
    def validate_operand(self):
        if self.field in ("cvss", "epss", "percentile"):
            maximum = 10 if self.field == "cvss" else 1
            if (
                self.op not in ("gte", "lte", "eq")
                or type(self.value) not in (int, float)
                or not 0 <= self.value <= maximum
            ):
                raise ValueError("Invalid metric condition")
        elif self.field in ("kev", "exposed"):
            if self.op != "eq" or type(self.value) is not bool:
                raise ValueError("Boolean fields require eq and a boolean")
        elif self.op == "in":
            if (
                not isinstance(self.value, list)
                or not 1 <= len(self.value) <= 100
                or not all(isinstance(v, str) and len(v) <= 200 for v in self.value)
            ):
                raise ValueError("in requires a bounded list of strings")
        elif (
            self.op not in ("eq", "contains")
            or not isinstance(self.value, str)
            or not 1 <= len(self.value) <= 200
        ):
            raise ValueError("Invalid text condition")
        return self


class Group(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["all", "any", "not"]
    children: list[Annotated[Union[Condition, "Group"], Field(discriminator="kind")]] = Field(
        min_length=1, max_length=30
    )

    @model_validator(mode="after")
    def validate_not(self):
        if self.kind == "not" and len(self.children) != 1:
            raise ValueError("not requires one child")
        return self


Group.model_rebuild()
Expression = Annotated[Condition | Group, Field(discriminator="kind")]


class Rule(Document):
    assets: list[str] = Field(default_factory=list, max_length=200)
    groups: list[str] = Field(default_factory=list, max_length=100)
    condition: Expression
    destinations: list[str] = Field(min_length=1, max_length=20)
    format: Literal["compact", "detailed"] = "compact"
    renotify_changes: bool = True

    @model_validator(mode="after")
    def validate_complexity(self):
        def count(node, depth):
            if depth > 8:
                raise ValueError("Rule nesting exceeds eight levels")
            return 1 + (
                sum(count(child, depth + 1) for child in node.children)
                if isinstance(node, Group)
                else 0
            )

        if count(self.condition, 0) > 100:
            raise ValueError("Rule contains too many conditions")
        return self


class DeliveryWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: list[Annotated[int, Field(strict=True, ge=0, le=6)]] = Field(min_length=1, max_length=7)
    start: str = Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    end: str = Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")

    @model_validator(mode="after")
    def validate_window(self):
        if self.start == self.end:
            raise ValueError("Delivery window start and end must differ")
        if len(set(self.days)) != len(self.days):
            raise ValueError("Delivery window days must be unique")
        return self


class DeliverySchedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = Field(min_length=1, max_length=100)
    windows: list[DeliveryWindow] = Field(min_length=1, max_length=14)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Choose a valid installed IANA timezone") from None
        return value


class Connector(Document):
    kind: Literal["telegram", "discord", "slack", "smtp", "webhook", "ntfy", "gotify"] = "telegram"
    token_env: str = Field(default="TELEGRAM_BOT_TOKEN", pattern=r"^[A-Z][A-Z0-9_]{0,99}$")
    chat_id: str = Field(default="", max_length=33)
    webhook_env: str = Field(default="", max_length=100)
    webhook_signing_env: str = Field(
        default="VULNRELAY_WEBHOOK_KEY", pattern=r"^VULNRELAY_WEBHOOK_KEY[A-Z0-9_]{0,70}$"
    )
    push_token_env: str = Field(
        default="VULNRELAY_NTFY_TOKEN", pattern=r"^VULNRELAY_(?:NTFY|GOTIFY)_TOKEN[A-Z0-9_]{0,70}$"
    )
    ntfy_topic: str = Field(default="", max_length=64)
    smtp_host_env: str = Field(
        default="VULNRELAY_SMTP_HOST", pattern=r"^VULNRELAY_SMTP_HOST[A-Z0-9_]{0,70}$"
    )
    smtp_port_env: str = Field(
        default="VULNRELAY_SMTP_PORT", pattern=r"^VULNRELAY_SMTP_PORT[A-Z0-9_]{0,70}$"
    )
    smtp_user_env: str = Field(
        default="VULNRELAY_SMTP_USER", pattern=r"^VULNRELAY_SMTP_USER[A-Z0-9_]{0,70}$"
    )
    smtp_password_env: str = Field(
        default="VULNRELAY_SMTP_PASSWORD", pattern=r"^VULNRELAY_SMTP_PASSWORD[A-Z0-9_]{0,70}$"
    )
    smtp_from: str = Field(default="", max_length=254)
    smtp_to: str = Field(default="", max_length=254)
    min_interval_seconds: float = Field(default=3.1, ge=1.1, le=3600, allow_inf_nan=False)
    delivery_schedule: DeliverySchedule | None = None

    @model_validator(mode="after")
    def validate_destination(self):
        import re

        if self.kind == "telegram" and not re.fullmatch(
            r"(?:-?\d{1,30}|@[A-Za-z0-9_]{5,32})", self.chat_id
        ):
            raise ValueError("Telegram requires a valid chat ID")
        if self.kind in ("discord", "slack", "webhook", "ntfy", "gotify") and not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,99}", self.webhook_env
        ):
            raise ValueError("A webhook environment variable name is required")
        if self.kind == "webhook" and not re.fullmatch(
            r"VULNRELAY_WEBHOOK_URL[A-Z0-9_]{0,70}", self.webhook_env
        ):
            raise ValueError("Generic webhook URLs must use a dedicated environment variable")
        if self.kind in ("ntfy", "gotify"):
            prefix = self.kind.upper()
            if not re.fullmatch(rf"VULNRELAY_{prefix}_URL[A-Z0-9_]{{0,70}}", self.webhook_env):
                raise ValueError("Push server URL must use a dedicated environment variable")
            if not re.fullmatch(rf"VULNRELAY_{prefix}_TOKEN[A-Z0-9_]{{0,70}}", self.push_token_env):
                raise ValueError("Push token must use a dedicated environment variable")
            if self.kind == "ntfy" and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.ntfy_topic):
                raise ValueError("ntfy requires a topic of letters, digits, dashes or underscores")
        if self.kind == "smtp":
            address = r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
            for value in (self.smtp_from, self.smtp_to):
                if not re.fullmatch(address, value) or ".." in value:
                    raise ValueError("SMTP requires one valid sender and recipient address")
        return self
