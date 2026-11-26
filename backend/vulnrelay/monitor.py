"""A restart-safe polling loop with persisted schedule and one monitor per database."""

import json
import logging
import random
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url

from vulnrelay.config import Settings
from vulnrelay.delivery import deliver_one
from vulnrelay.digests import schedule_due
from vulnrelay.epss_bulk import refresh as refresh_epss
from vulnrelay.kev import sync as sync_kev
from vulnrelay.logging_config import configure
from vulnrelay.news import refresh as refresh_news
from vulnrelay.news import settings as news_settings
from vulnrelay.nvd import retry_after_seconds, transient_failure
from vulnrelay.nvd import sync as sync_nvd
from vulnrelay.opencve import refresh as refresh_opencve
from vulnrelay.opencve import retry_delay as opencve_retry_delay
from vulnrelay.osv import refresh as refresh_osv
from vulnrelay.pipeline import correlate

try:
    import fcntl
except ImportError:  # Windows can use configuration commands; the monitor remains Unix-only.
    fcntl = None

logger = logging.getLogger(__name__)


@contextmanager
def monitor_lock(engine: Engine):
    if engine.dialect.name == "sqlite":
        if fcntl is None:
            raise RuntimeError(
                "Native monitoring requires Unix file locking; use Docker on Windows"
            )
        database = make_url(engine.url).database
        if not database or database == ":memory:":
            raise ValueError("Monitoring needs a persistent database")
        lock_path = Path(database).resolve().with_suffix(".monitor.lock")
        with lock_path.open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another monitor or synchronization is running") from None
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    elif engine.dialect.name == "postgresql":
        with engine.connect() as connection:
            if not connection.execute(text("SELECT pg_try_advisory_lock(86317901)")).scalar():
                raise RuntimeError("Another monitor or synchronization is running")
            try:
                yield
            finally:
                connection.execute(text("SELECT pg_advisory_unlock(86317901)"))
    else:
        raise ValueError("Unsupported monitoring database")


def state(engine: Engine) -> dict:
    with engine.connect() as connection:
        return {
            row.name: json.loads(row.value)
            for row in connection.execute(text("SELECT name, value FROM engine_state"))
        }


def set_state(engine: Engine, name: str, value):
    set_states(engine, {name: value})


def set_states(engine: Engine, values: dict):
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO engine_state (name,value) VALUES (:name,:value)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value"""),
            [{"name": name, "value": json.dumps(value)} for name, value in values.items()],
        )


def cycle(
    engine: Engine,
    settings: Settings,
    *,
    now: float | None = None,
    sync_sources: bool = True,
    process_deliveries: bool = True,
) -> dict:
    current = time.time() if now is None else now
    schedule = state(engine)
    outcomes = {}
    sources = [
        ("nvd", lambda: sync_nvd(engine, api_key=settings.nvd_api_key.get_secret_value())),
        ("cisa_kev", lambda: sync_kev(engine)),
        ("epss", lambda: refresh_epss(engine)),
    ]
    if settings.opencve_enabled:
        sources.append(
            ("opencve", lambda: refresh_opencve(engine, batch_size=settings.opencve_batch_size))
        )
    if settings.osv_enabled:
        sources.append(("osv", lambda: refresh_osv(engine)))
    if news_settings(engine).enabled:
        sources.append(("news", lambda: refresh_news(engine)))
    for source, action in sources:
        if sync_sources and current >= schedule.get(f"next_{source}", 0):
            deferred_until = 0
            nvd_failures = 0
            nvd_retry_delay = 0.0
            try:
                records = action()
                outcomes[source] = {
                    "ok": not (
                        (source == "osv" and records["assets_failed"])
                        or (source == "news" and records["failed"])
                    ),
                    "records": records,
                }
                if source == "osv" and records.get("retry_after"):
                    deferred_until = (time.time() if now is None else current) + records[
                        "retry_after"
                    ]
            except Exception as exc:  # noqa: BLE001 - isolate untrusted upstream adapters
                outcomes[source] = {"ok": False}
                logger.warning("Source synchronization failed", extra={"source": source})
                if source == "nvd" and transient_failure(exc):
                    nvd_failures = schedule.get("failures_nvd", 0) + 1
                    base = min(1800, 120 * 2 ** min(nvd_failures - 1, 4))
                    nvd_retry_delay = min(1800, base + random.uniform(0, base / 4))
                    if isinstance(exc, httpx.HTTPStatusError):
                        nvd_retry_delay = max(nvd_retry_delay, retry_after_seconds(exc.response))
                if source == "opencve" and isinstance(exc, httpx.HTTPStatusError):
                    deferred_until = time.time() + opencve_retry_delay(exc.response)
            finished = time.time() if now is None else current
            next_attempt = max(
                deferred_until,
                finished
                + (
                    nvd_retry_delay
                    or (86400 if source == "epss" else settings.sync_interval_minutes * 60)
                ),
            )
            updates = {f"next_{source}": next_attempt}
            if source == "nvd":
                # Persist one consistent schedule, independently of the unchanged CVE cursor.
                updates.update(failures_nvd=nvd_failures, last_attempt_nvd=finished)
            set_states(engine, updates)
    result = correlate(engine, enqueue=True, limit=0)
    reports_queued = schedule_due(engine, now=current)
    deliveries = []
    for _ in range(50 if process_deliveries else 0):
        delivery = deliver_one(engine)
        if delivery is None:
            break
        deliveries.append(delivery)
    set_state(engine, "last_cycle", current)
    return {
        "sources": outcomes,
        "evaluations": result["evaluations"],
        "queued": result["queued"],
        "reports_queued": reports_queued,
        "deliveries": deliveries,
    }


def run(engine: Engine, settings: Settings):
    configure(settings.log_level)
    stop = threading.Event()
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, lambda *_: stop.set())

    def pump_deliveries():
        last_heartbeat = 0
        while not stop.is_set():
            delivery = None
            try:
                if time.time() - last_heartbeat >= 30:
                    set_state(engine, "delivery_heartbeat", time.time())
                    last_heartbeat = time.time()
                delivery = deliver_one(engine)
                if delivery:
                    logger.info("Delivery processed", extra={"deliveries": 1})
            except Exception:  # noqa: BLE001 - a failed delivery must not stop source monitoring
                logger.error("Delivery worker failed; claims will expire and recover")
            # Connector deadlines govern pacing; do not add a fixed sleep after each send.
            stop.wait(0.25 if delivery is None else 0)

    try:
        with monitor_lock(engine):
            pump = threading.Thread(target=pump_deliveries, name="vulnrelay-delivery", daemon=True)
            pump.start()
            try:
                while not stop.is_set():
                    try:
                        result = cycle(engine, settings, process_deliveries=False)
                        if result["queued"] or result["sources"]:
                            logger.info(
                                "Monitoring cycle completed",
                                extra={"queued": result["queued"], "deliveries": 0},
                            )
                    except Exception:  # noqa: BLE001 - keep the long-running worker alive
                        logger.error("Monitoring cycle failed; retrying after delay")
                    stop.wait(10)
            finally:
                stop.set()
                pump.join(timeout=30)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
