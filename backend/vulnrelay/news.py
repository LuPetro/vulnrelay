"""Opt-in security news from fixed RSS feeds, with durable, source-attributed alerts."""

import hashlib
import json
import re
import time
from datetime import UTC
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit
from uuid import uuid4
from xml.etree import ElementTree

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.store import list_documents

FEEDS = {
    "cisa": {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    "bleepingcomputer": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
    "thehackernews": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
}
MAX_FEED_BYTES = 2_000_000
MAX_ITEMS = 100


class NewsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    sources: list[str] = Field(default_factory=lambda: list(FEEDS), max_length=len(FEEDS))
    notifications: bool = False
    destinations: list[str] = Field(default_factory=list, max_length=20)
    categories: list[str] = Field(
        default_factory=lambda: ["vulnerability", "security"], max_length=2
    )

    @field_validator("sources")
    @classmethod
    def valid_sources(cls, value):
        if len(value) != len(set(value)) or any(item not in FEEDS for item in value):
            raise ValueError("Unknown news source")
        return value

    @field_validator("categories")
    @classmethod
    def valid_categories(cls, value):
        if len(value) != len(set(value)) or any(
            item not in {"vulnerability", "security"} for item in value
        ):
            raise ValueError("Unknown news category")
        return value

    @field_validator("destinations")
    @classmethod
    def unique_destinations(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Duplicate destination")
        return value


def settings(engine: Engine) -> NewsSettings:
    with engine.connect() as connection:
        raw = connection.execute(
            text("SELECT value FROM engine_state WHERE name='news_settings'")
        ).scalar_one_or_none()
    try:
        return NewsSettings.model_validate_json(raw) if raw else NewsSettings()
    except ValueError:
        return NewsSettings()


def save_settings(engine: Engine, document: dict) -> NewsSettings:
    config = NewsSettings.model_validate(document)
    connectors = {row["id"] for row in list_documents(engine, "connectors")}
    if set(config.destinations) - connectors or (config.notifications and not config.destinations):
        raise ValueError("Choose valid destinations")
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO engine_state(name,value) VALUES ('news_settings',:value)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value"""),
            {"value": config.model_dump_json()},
        )
        connection.execute(
            text("""INSERT INTO engine_state(name,value) VALUES ('next_news','0')
            ON CONFLICT(name) DO UPDATE SET value=excluded.value""")
        )
    return config


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def _plain(value: str, limit: int) -> str:
    parser = _Text()
    parser.feed(value[:5000])
    return " ".join(" ".join(parser.parts).split())[:limit]


def _category(title: str) -> str:
    return (
        "vulnerability"
        if re.search(
            r"\b(?:cve-\d{4}-\d+|vulnerabilit(?:y|ies)|zero.day|flaw|exploit|rce|security update|patch(?:es|ed)?)\b",
            title,
            re.I,
        )
        else "security"
    )


def parse_feed(source: str, body: bytes) -> list[dict]:
    if len(body) > MAX_FEED_BYTES or b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
        raise ValueError("Unsafe or oversized feed")
    root = ElementTree.fromstring(body)
    if root.tag != "rss" or root.find("channel") is None:
        raise ValueError("Unsupported feed format")
    result = []
    for item in root.findall("./channel/item")[:MAX_ITEMS]:
        title = _plain(item.findtext("title") or "", 300)
        url = (item.findtext("link") or "").strip()
        parsed = urlsplit(url)
        if (
            not title
            or len(url) > 600
            or not url.isascii()
            or any(ord(char) <= 32 or ord(char) == 127 for char in url)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            continue
        # Identity follows the published link, so repeated polls don't resend an article.
        identifier = hashlib.sha256(f"{source}\n{url}".encode()).hexdigest()
        published = None
        try:
            date = parsedate_to_datetime(item.findtext("pubDate") or "")
            published = (
                (date if date.tzinfo else date.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
            )
        except (TypeError, ValueError, OverflowError):
            pass
        result.append(
            {
                "id": identifier,
                "source": source,
                "title": title,
                "url": url,
                "category": _category(title),
                "published": published,
            }
        )
    return result


def _download(client: httpx.Client, url: str) -> bytes:
    with client.stream("GET", url, follow_redirects=False) as response:
        response.raise_for_status()
        parts, size = [], 0
        for part in response.iter_bytes():
            size += len(part)
            if size > MAX_FEED_BYTES:
                raise ValueError("Feed exceeds size limit")
            parts.append(part)
        return b"".join(parts)


def refresh(
    engine: Engine, *, client: httpx.Client | None = None, now: float | None = None
) -> dict:
    config = settings(engine)
    if not config.enabled:
        return {"sources": 0, "new": 0, "failed": 0}
    current = time.time() if now is None else now
    counts = {"sources": 0, "new": 0, "failed": 0}
    owned = client is None
    client = client or httpx.Client(
        timeout=15, trust_env=False, headers={"User-Agent": "VulnRelay/0.1 security news reader"}
    )
    try:
        for source in config.sources:
            try:
                items = parse_feed(source, _download(client, FEEDS[source]["url"]))
                with engine.begin() as connection:
                    previous = connection.execute(
                        text("SELECT last_success FROM news_feed_state WHERE source=:source"),
                        {"source": source},
                    ).scalar_one_or_none()
                    for item in items:
                        inserted = connection.execute(
                            text("""INSERT INTO news_items
                            (id,source,title,url,category,published,discovered)
                            VALUES (:id,:source,:title,:url,:category,:published,:discovered)
                            ON CONFLICT(id) DO NOTHING"""),
                            {**item, "discovered": current},
                        ).rowcount
                        counts["new"] += inserted
                        # Establish a baseline without flooding existing connectors with history.
                        if (
                            inserted
                            and previous is not None
                            and config.notifications
                            and item["category"] in config.categories
                        ):
                            for destination in config.destinations:
                                key = hashlib.sha256(
                                    f"news:{item['id']}:{destination}".encode()
                                ).hexdigest()
                                connection.execute(
                                    text("""INSERT INTO outbox
                                    (id,event_key,connector_id,payload,state,attempts,available_at,created_at)
                                    VALUES (:id,:key,:connector,:payload,'pending',0,:now,:now)
                                    ON CONFLICT(event_key) DO NOTHING"""),
                                    {
                                        "id": str(uuid4()),
                                        "key": key,
                                        "connector": destination,
                                        "payload": json.dumps(
                                            {"news": True, "news_id": item["id"]}
                                        ),
                                        "now": current,
                                    },
                                )
                    connection.execute(
                        text("""INSERT INTO news_feed_state(source,last_success,last_attempt,last_error)
                        VALUES (:source,:now,:now,NULL) ON CONFLICT(source) DO UPDATE SET
                        last_success=excluded.last_success,last_attempt=excluded.last_attempt,last_error=NULL"""),
                        {"source": source, "now": current},
                    )
                counts["sources"] += 1
            except (httpx.HTTPError, ValueError, ElementTree.ParseError):
                counts["failed"] += 1
                with engine.begin() as connection:
                    connection.execute(
                        text("""INSERT INTO news_feed_state(source,last_attempt,last_error)
                        VALUES (:source,:now,'Feed unavailable or invalid') ON CONFLICT(source) DO UPDATE SET
                        last_attempt=excluded.last_attempt,last_error=excluded.last_error"""),
                        {"source": source, "now": current},
                    )
    finally:
        if owned:
            client.close()
    return counts


def list_news(engine: Engine) -> dict:
    with engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT * FROM news_items ORDER BY COALESCE(published,'') DESC,discovered DESC LIMIT 200"
                )
            )
            .mappings()
            .all()
        )
        states = {
            row["source"]: dict(row)
            for row in connection.execute(text("SELECT * FROM news_feed_state")).mappings()
        }
    items = []
    for row in rows:
        item = dict(row)
        title = item["title"]
        if re.search(
            r"\b(?:actively exploited|known exploited|exploited in the wild)\b", title, re.I
        ):
            item["highlight"] = "Headline mentions exploitation"
        elif re.search(r"\bzero[- ]day\b", title, re.I):
            item["highlight"] = "Headline mentions a zero-day"
        else:
            item["highlight"] = None
        items.append(item)
    return {
        "settings": settings(engine).model_dump(),
        "sources": [
            {"id": key, "name": value["name"], **states.get(key, {})}
            for key, value in FEEDS.items()
        ],
        "items": items,
    }


def refresh_news(engine: Engine, payload: dict, destination: str) -> tuple[dict | None, str | None]:
    config = settings(engine)
    if not config.enabled or not config.notifications or destination not in config.destinations:
        return None, "News notifications disabled or destination removed"
    with engine.connect() as connection:
        row = (
            connection.execute(
                text("SELECT * FROM news_items WHERE id=:id"), {"id": payload.get("news_id")}
            )
            .mappings()
            .first()
        )
    if not row or row["source"] not in config.sources or row["category"] not in config.categories:
        return None, "News item or subscription no longer available"
    return {
        "news": True,
        "news_id": row["id"],
        "item": {**dict(row), "source_name": FEEDS[row["source"]]["name"]},
    }, None
