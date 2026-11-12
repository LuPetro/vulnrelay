"""Validated, portable configuration. Secrets are environment references only."""

from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True


class Asset(Document):
    kind: Literal["vendor", "product", "vendor_product", "cpe", "keyword"]
    vendor: str = Field(default="", max_length=200)
    product: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=100)
    cpe: str = Field(default="", max_length=1000)
    keyword: str = Field(default="", max_length=200)
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
        }[self.kind]
        if not all(item.strip() for item in required):
            raise ValueError("The selected asset type needs its identity fields")
        if self.kind == "cpe":
            from vulnrelay.matching import split_cpe

            split_cpe(self.cpe)
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


class Connector(Document):
    kind: Literal["telegram"] = "telegram"
    token_env: str = Field(default="TELEGRAM_BOT_TOKEN", pattern=r"^[A-Z][A-Z0-9_]{0,99}$")
    chat_id: str = Field(pattern=r"^(?:-?\d{1,30}|@[A-Za-z0-9_]{5,32})$")
