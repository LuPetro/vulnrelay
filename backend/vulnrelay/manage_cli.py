"""Configuration and notification CLI commands shared with the engine API."""

import json
from pathlib import Path

import typer
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from vulnrelay.catalog import PACKS, CatalogSelection, catalog, import_selection
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.delivery import deliver_one, enqueue_test, history
from vulnrelay.monitor import cycle, monitor_lock, run
from vulnrelay.pipeline import correlate
from vulnrelay.queue import ClearQueue, clear_queue, queue_status
from vulnrelay.store import delete_document, list_documents, save_document

app = typer.Typer(no_args_is_help=True)
catalog_app = typer.Typer(
    no_args_is_help=True, help="Browse technologies and import starter packs."
)
app.add_typer(catalog_app, name="catalog")
queue_app = typer.Typer(no_args_is_help=True, help="Inspect or discard waiting notifications.")
app.add_typer(queue_app, name="queue")


@queue_app.command("status")
def queue_status_command():
    """Show counts and destination cooldowns without sending messages."""
    _execute(queue_status)


@queue_app.command("clear")
def queue_clear_command(yes: bool = typer.Option(False, "--yes"), connector: str | None = None):
    """Discard pending/retry events in a captured snapshot; keep history and in-flight requests."""

    def action(engine):
        snapshot = queue_status(engine)
        if not yes and not typer.confirm(
            "Discard waiting messages? Unchanged events stay dismissed; history is retained."
        ):
            return {"cleared": 0}
        return clear_queue(engine, ClearQueue(before=snapshot["as_of"], connector_id=connector))

    _execute(action)


@catalog_app.command("list")
def catalog_list(query: str = ""):
    """Search the bundled offline catalog; includes pack definitions."""
    typer.echo(json.dumps(catalog(query), ensure_ascii=False, indent=2))


@catalog_app.command("add")
def catalog_add(file: Path, preview: bool = False):
    """Import a JSON selection of product IDs and context, or preview without writing."""
    _execute(
        lambda engine: import_selection(
            engine, CatalogSelection.model_validate_json(file.read_text()), preview=preview
        )
    )


@catalog_app.command("pack")
def catalog_pack(
    pack_id: str, group: str = "production", environment: str = "production", preview: bool = False
):
    """Import a starter pack. Repeated imports reuse existing assets in the same context."""

    def action(engine):
        pack = next((p for p in PACKS if p["id"] == pack_id), None)
        if pack is None:
            raise ValueError("Unknown catalog pack")
        return import_selection(
            engine,
            CatalogSelection(products=pack["products"], group=group, environment=environment),
            preview=preview,
        )

    _execute(action)


def _engine():
    return create_database_engine(get_settings().database_url)


def _execute(action):
    engine = _engine()
    try:
        value = action(engine)
        typer.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))
    except (ValidationError, ValueError, SQLAlchemyError, RuntimeError, OSError) as exc:
        # Validation messages may contain submitted content; do not print raw configuration.
        typer.echo(
            f"Operation failed ({type(exc).__name__}). Check input, schema migrations and engine status.",
            err=True,
        )
        raise typer.Exit(1) from None
    finally:
        engine.dispose()


def register_configuration_commands(root):
    for collection in ("assets", "rules", "connectors"):
        group = typer.Typer(no_args_is_help=True)
        root.add_typer(group, name=collection)

        def make_commands(table, target):
            @target.command("list")
            def list_command():
                """List configured entries as JSON."""
                _execute(lambda engine: list_documents(engine, table))

            @target.command("add")
            def add_command(file: Path):
                """Add one entry from a JSON file; connector secrets must be environment references."""
                _execute(lambda engine: save_document(engine, table, json.loads(file.read_text())))

            @target.command("delete")
            def delete_command(entry_id: str):
                """Delete a configuration entry."""
                _execute(lambda engine: {"deleted": delete_document(engine, table, entry_id)})

            @target.command("update")
            def update_command(entry_id: str, file: Path):
                """Replace one entry from a JSON file."""
                _execute(
                    lambda engine: save_document(
                        engine, table, json.loads(file.read_text()), entry_id
                    )
                )

        make_commands(collection, group)
        if collection == "connectors":

            @group.command("test")
            def connector_test_alias(connector_id: str):
                _execute(lambda engine: {"queued": enqueue_test(engine, connector_id)})
        elif collection == "rules":

            @group.command("test")
            def rule_test_alias(rule_id: str):
                _execute(lambda engine: correlate(engine, rule_id=rule_id))


@app.command("evaluate")
def evaluate_command(enqueue: bool = False, rule_id: str | None = None, cve_id: str | None = None):
    """Explain asset and rule matches; optionally add matching alerts to the queue."""
    _execute(lambda engine: correlate(engine, enqueue=enqueue, rule_id=rule_id, cve_id=cve_id))


@app.command("test-connector")
def test_connector(connector_id: str):
    """Queue a test notification. Use deliver or monitor to send it."""
    _execute(lambda engine: {"queued": enqueue_test(engine, connector_id)})


@app.command("deliver")
def deliver_command():
    """Attempt one queued delivery, including retries due now."""
    _execute(deliver_one)


@app.command("history")
def history_command():
    """Inspect delivery states and failures."""
    _execute(history)


@app.command("monitor")
def monitor_command(once: bool = False, no_sync: bool = False):
    """Monitor continuously, or run one full cycle; --no-sync applies to --once."""

    def action(engine):
        if once:
            with monitor_lock(engine):
                return cycle(engine, get_settings(), sync_sources=not no_sync)
        if no_sync:
            raise ValueError("--no-sync requires --once")
        run(engine, get_settings())
        return {"status": "stopped"}

    _execute(action)


@app.command("doctor")
def doctor_command():
    """Check database schema, source health and monitor timestamps."""
    from sqlalchemy import text

    from vulnrelay.monitor import state

    def check(engine):
        with engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            sources = [
                dict(row)
                for row in connection.execute(
                    text("SELECT source,last_success_at,last_error FROM source_state")
                ).mappings()
            ]
        return {"schema_revision": revision, "sources": sources, "engine": state(engine)}

    _execute(check)


@app.command("backup")
def backup_command(destination: Path):
    """Create a private, consistent SQLite backup; never overwrite a file."""
    from vulnrelay.operations import backup_sqlite

    _execute(lambda engine: backup_sqlite(engine, destination))


@app.command("engine-health")
def engine_health_command():
    """Exit successfully only if a delivery worker heartbeat is recent."""
    from vulnrelay.operations import worker_health

    engine = _engine()
    try:
        healthy = worker_health(engine)
    except (SQLAlchemyError, ValueError):
        healthy = False
    finally:
        engine.dispose()
    typer.echo("healthy" if healthy else "no recent delivery worker heartbeat")
    if not healthy:
        raise typer.Exit(1)
