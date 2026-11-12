import json

import httpx
import typer
import uvicorn
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.epss import lookup as lookup_epss
from vulnrelay.kev import sync as sync_kev
from vulnrelay.manage_cli import app as engine_commands
from vulnrelay.manage_cli import register_configuration_commands
from vulnrelay.monitor import monitor_lock
from vulnrelay.nvd import sync as sync_nvd

app = typer.Typer(no_args_is_help=True, help="VulnRelay administration.")
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(engine_commands)
register_configuration_commands(app)


@app.command()
def start():
    """Start the local API. Remote access is not yet supported."""
    settings = get_settings()
    if settings.host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo("Remote exposure is unsupported: authentication is not implemented.", err=True)
        raise typer.Exit(1)
    uvicorn.run(
        "vulnrelay.api:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


@app.command()
def status(json_output: bool = typer.Option(False, "--json")):
    """Check database connectivity; does not imply monitoring is running."""
    from vulnrelay.monitor import state

    engine = create_database_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        try:
            schedule = state(engine)
        except SQLAlchemyError:
            schedule = {}
    except SQLAlchemyError:
        typer.echo("Database unavailable", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    result = {
        "database": "reachable",
        "last_cycle": schedule.get("last_cycle"),
        "schedule": schedule,
    }
    typer.echo(
        json.dumps(result)
        if json_output
        else f"Database reachable; last monitoring cycle: {schedule.get('last_cycle', 'never')}"
    )


@config_app.command("validate")
def validate_config():
    """Validate environment settings without displaying secrets."""
    try:
        get_settings()
    except ValidationError:
        typer.echo("Invalid configuration. Check environment settings.", err=True)
        raise typer.Exit(1) from None
    typer.echo("Configuration valid.")


@app.command()
def sync(days: int = typer.Option(7, min=1, max=120)):
    """Synchronize NVD changes; --days applies only to the first run."""
    settings = get_settings()
    engine = create_database_engine(settings.database_url)
    try:
        with monitor_lock(engine):
            count = sync_nvd(engine, api_key=settings.nvd_api_key.get_secret_value(), days=days)
    except (SQLAlchemyError, ValueError, TypeError, KeyError, RuntimeError, httpx.HTTPError):
        typer.echo("NVD sync failed. Check connectivity and run database migrations.", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    typer.echo(f"NVD synchronization completed: {count} records processed.")


@app.command("sync-kev")
def sync_kev_command():
    """Download and store the CISA known exploited vulnerabilities catalog."""
    engine = create_database_engine(get_settings().database_url)
    try:
        with monitor_lock(engine):
            count = sync_kev(engine)
    except (SQLAlchemyError, ValueError, TypeError, KeyError, RuntimeError, httpx.HTTPError):
        typer.echo("CISA KEV sync failed. Check connectivity and run migrations.", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    typer.echo(f"CISA KEV synchronization completed: {count} records stored.")


@app.command()
def cve(cve_id: str):
    """Show locally stored NVD and CISA KEV data for one CVE as JSON."""
    engine = create_database_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            nvd = (
                connection.execute(
                    text(
                        "SELECT id, description, cvss_score, severity, cvss_version, status FROM vulnerabilities WHERE id=:id"
                    ),
                    {"id": cve_id.upper()},
                )
                .mappings()
                .one_or_none()
            )
            kev = connection.execute(
                text("SELECT raw FROM kev_entries WHERE cve_id=:id"), {"id": cve_id.upper()}
            ).scalar_one_or_none()
            epss = (
                connection.execute(
                    text("SELECT score, percentile, measured_on FROM epss_scores WHERE cve_id=:id"),
                    {"id": cve_id.upper()},
                )
                .mappings()
                .one_or_none()
            )
            catalog = connection.execute(
                text("SELECT checkpoint FROM source_state WHERE source='cisa_kev'")
            ).scalar_one_or_none()
    except SQLAlchemyError:
        typer.echo("Database unavailable or migrations missing.", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    if not nvd and not kev and not epss:
        typer.echo("CVE not found locally.", err=True)
        raise typer.Exit(1)
    result = {
        "id": cve_id.upper(),
        "nvd": dict(nvd) if nvd else None,
        "cisa_kev": json.loads(kev) if kev else None,
        "kev_status": "listed" if kev else "not listed" if catalog else "unknown",
        "kev_catalog_released": catalog,
        "epss": dict(epss) if epss else None,
    }
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("lookup-epss")
def lookup_epss_command(cve_id: str):
    """Look up and save the current FIRST EPSS score for one CVE."""
    engine = create_database_engine(get_settings().database_url)
    try:
        result = lookup_epss(engine, cve_id)
    except (SQLAlchemyError, ValueError, TypeError, KeyError, RuntimeError, httpx.HTTPError):
        typer.echo("EPSS lookup failed. Check the CVE, connectivity, and migrations.", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    if result is None:
        typer.echo("No EPSS score available for this CVE.")
    else:
        typer.echo(json.dumps(result))


@app.command()
def init():
    """Create or upgrade the database using packaged migrations."""
    from importlib.resources import files

    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(files("vulnrelay") / "migrations"))
    try:
        command.upgrade(config, "head")
    except SQLAlchemyError:
        typer.echo("Database initialization failed.", err=True)
        raise typer.Exit(1) from None
    typer.echo("Database initialized.")


def _version_callback(value: bool):
    if value:
        from vulnrelay import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
):
    """Operate a local vulnerability notification engine."""
