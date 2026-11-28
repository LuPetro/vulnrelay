"""Read-only Telegram setup checks with bounded, secret-safe responses."""

import json
import math
import re
import time
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.engine import Engine

from vulnrelay.delivery import _secret

MAX_RESPONSE_BYTES = 512_000


class TelegramProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token_env: str = Field(default="TELEGRAM_BOT_TOKEN", pattern=r"^[A-Z][A-Z0-9_]{0,99}$")
    mode: Literal["bot", "chats"] = "bot"


class ProbeError(Exception):
    def __init__(self, code: str, message: str, retry_after: int = 0):
        self.code, self.message, self.retry_after = code, message, retry_after


def reserve_probe(engine: Engine, *, wait: int = 2, now: float | None = None) -> int:
    """A shared persistent deadline prevents concurrent setup checks from flooding Telegram."""
    current = time.time() if now is None else now
    with engine.begin() as connection:
        claimed = connection.execute(
            text("""INSERT INTO engine_state(name,value) VALUES ('telegram_setup_next',:next)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value
            WHERE CAST(engine_state.value AS FLOAT)<=:now"""),
            {"next": json.dumps(current + wait), "now": current},
        )
        if claimed.rowcount == 1:
            return 0
        due = connection.execute(
            text("SELECT value FROM engine_state WHERE name='telegram_setup_next'")
        ).scalar_one()
    return max(1, math.ceil(float(due) - current))


def defer_probe(engine: Engine, seconds: int):
    due = time.time() + seconds
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO engine_state(name,value) VALUES ('telegram_setup_next',:next)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value
            WHERE CAST(engine_state.value AS FLOAT)<:due"""),
            {"next": json.dumps(due), "due": due},
        )


def _request(client: httpx.Client, token: str, method: str) -> dict | list:
    parameters = {"timeout": 0, "limit": 100} if method == "getUpdates" else {}
    with client.stream(
        "POST",
        f"https://api.telegram.org/bot{token}/{method}",
        json=parameters,
        follow_redirects=False,
    ) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ProbeError(
                    "invalid_response",
                    "Telegram's response was too large. Try entering the chat ID manually.",
                )
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            data = {}
        data = data if isinstance(data, dict) else {}
        code = response.status_code
        if code == 429 or data.get("error_code") == 429:
            parameters = data.get("parameters")
            delay = parameters.get("retry_after", 60) if isinstance(parameters, dict) else 60
            delay = min(86400, max(1, delay)) if type(delay) is int else 60
            raise ProbeError(
                "rate_limited", "Telegram asked us to wait before checking again.", delay
            )
        if code == 401 or data.get("error_code") == 401:
            raise ProbeError(
                "invalid_token",
                "Telegram rejected this token. Check BotFather and the server environment, then recreate both containers.",
            )
        if code == 409 or data.get("error_code") == 409:
            raise ProbeError(
                "updates_busy",
                "Another integration is receiving this bot's updates. Enter the chat ID manually or try again later.",
            )
        if code != 200 or data.get("ok") is not True:
            raise ProbeError(
                "telegram_error", "Telegram could not complete this check. Please try again later."
            )
        result = data.get("result")
        if not isinstance(result, (dict, list)):
            raise ValueError
        return result


def _label(value: object, token: str) -> str:
    if not isinstance(value, str):
        return ""
    clean = value.replace(token, "[redacted]").encode("utf-8", errors="replace").decode()
    clean = re.sub(r"[\x00-\x1f\x7f]", " ", clean)
    return " ".join(clean.split())[:120]


def _chat_id(value: object) -> bool:
    return type(value) is int and 0 < abs(value) < 10**30


def probe(config: TelegramProbe, *, client: httpx.Client | None = None) -> dict:
    token = _secret(config.token_env).strip()
    if not token:
        return {
            "ok": False,
            "code": "missing_token",
            "message": "This token variable is empty or unavailable. Add it to the server's .env and recreate both containers.",
        }
    if not re.fullmatch(r"\d{5,20}:[A-Za-z0-9_-]{20,200}", token):
        return {
            "ok": False,
            "code": "invalid_token",
            "message": "The configured value does not look like a Telegram bot token. Copy the complete token from BotFather.",
        }
    owned = client is None
    client = client or httpx.Client(timeout=10, trust_env=False, follow_redirects=False)
    try:
        identity = _request(client, token, "getMe")
        if (
            not isinstance(identity, dict)
            or identity.get("is_bot") is not True
            or not _chat_id(identity.get("id"))
            or not isinstance(identity.get("username"), str)
            or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", identity["username"])
        ):
            raise ValueError
        bot = {
            "id": str(identity["id"]),
            "username": identity["username"],
            "name": _label(identity.get("first_name"), token),
        }
        webhook = _request(client, token, "getWebhookInfo")
        if not isinstance(webhook, dict) or not isinstance(webhook.get("url"), str):
            raise ValueError
        active = bool(webhook["url"])
        chats = {}
        if config.mode == "chats" and not active:
            updates = _request(client, token, "getUpdates")
            if not isinstance(updates, list):
                raise ValueError
            for update in updates[:100]:
                if not isinstance(update, dict):
                    continue
                for key in (
                    "message",
                    "edited_message",
                    "channel_post",
                    "edited_channel_post",
                    "my_chat_member",
                ):
                    event = update.get(key)
                    chat = event.get("chat") if isinstance(event, dict) else None
                    if (
                        not isinstance(chat, dict)
                        or not _chat_id(chat.get("id"))
                        or chat.get("type") not in ("private", "group", "supergroup", "channel")
                    ):
                        continue
                    identifier = str(chat["id"])
                    chats[identifier] = {
                        "id": identifier,
                        "type": chat["type"],
                        "name": _label(chat.get("title") or chat.get("first_name"), token)
                        or identifier,
                    }
        return {"ok": True, "bot": bot, "webhook_active": active, "chats": list(chats.values())}
    except ProbeError as error:
        return {
            "ok": False,
            "code": error.code,
            "message": error.message,
            "retry_after": error.retry_after,
        }
    except (httpx.HTTPError, ValueError, UnicodeError):
        # Telegram URLs and upstream error strings can contain the token.
        return {
            "ok": False,
            "code": "unavailable",
            "message": "Telegram is unreachable or returned an unexpected response. Please try again later.",
        }
    finally:
        if owned:
            client.close()
