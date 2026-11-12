"""Structured application logs; HTTP request logging stays disabled for token-bearing URLs."""

import json
import logging
import re
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record):
        message = re.sub(r"\d{5,20}:[A-Za-z0-9_-]{20,200}", "[REDACTED]", record.getMessage())
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        for key in ("source", "queued", "deliveries"):
            if hasattr(record, key):
                event[key] = getattr(record, key)
        return json.dumps(event)


def configure(level: str = "INFO"):
    application = logging.getLogger("vulnrelay")
    if not application.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        application.addHandler(handler)
    application.setLevel(getattr(logging, level.upper(), logging.INFO))
    application.propagate = False
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
