"""A restart-safe polling loop with persisted schedule and one monitor per database."""

import json
import logging
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
from vulnrelay.epss_bulk import refresh as refresh_epss
from vulnrelay.kev import sync as sync_kev
from vulnrelay.logging_config import configure
from vulnrelay.nvd import sync as sync_nvd
from vulnrelay.opencve import refresh as refresh_opencve
from vulnrelay.opencve import retry_delay as opencve_retry_delay
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
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO engine_state (name,value) VALUES (:name,:value)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value"""),
            {"name": name, "value": json.dumps(value)},
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
    for source, action in sources:
        if sync_sources and current >= schedule.get(f"next_{source}", 0):
            deferred_until = 0
            try:
                outcomes[source] = {"ok": True, "records": action()}
            except Exception as exc:  # noqa: BLE001 - isolate untrusted upstream adapters
                outcomes[source] = {"ok": False}
                logger.warning("Source synchronization failed", extra={"source": source})
                if source == "opencve" and isinstance(exc, httpx.HTTPStatusError):
                    deferred_until = time.time() + opencve_retry_delay(exc.response)
            set_state(
                engine,
                f"next_{source}",
                max(
                    deferred_until,
                    current + (86400 if source == "epss" else settings.sync_interval_minutes * 60),
                ),
            )
    result = correlate(engine, enqueue=True, limit=0)
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
            try:
                if time.time() - last_heartbeat >= 30:
                    set_state(engine, "delivery_heartbeat", time.time())
                    last_heartbeat = time.time()
                delivery = deliver_one(engine)
                if delivery:
                    logger.info("Delivery processed", extra={"deliveries": 1})
            except Exception:  # noqa: BLE001 - a failed delivery must not stop source monitoring
                logger.error("Delivery worker failed; claims will expire and recover")
            stop.wait(1)

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
