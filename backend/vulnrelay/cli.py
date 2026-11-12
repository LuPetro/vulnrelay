import json

import typer
import uvicorn
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine

app = typer.Typer(no_args_is_help=True, help="VulnRelay administration.")
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")


@app.command()
def start():
    """Start the local API. Remote access is not yet supported."""
    settings = get_settings()
    if settings.host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo("Remote exposure is unsupported: authentication is not implemented.", err=True)
        raise typer.Exit(1)
    uvicorn.run("vulnrelay.api:app", host=settings.host, port=settings.port,
                log_level=settings.log_level.lower())


@app.command()
def status(json_output: bool = typer.Option(False, "--json")):
    """Check database connectivity; does not imply monitoring is running."""
    engine = create_database_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        typer.echo("Database unavailable", err=True)
        raise typer.Exit(1) from None
    finally:
        engine.dispose()
    result = {"database": "reachable", "monitoring": "not implemented"}
    typer.echo(json.dumps(result) if json_output else "Database reachable; monitoring not implemented.")


@config_app.command("validate")
def validate_config():
    """Validate environment settings without displaying secrets."""
    try:
        get_settings()
    except ValidationError:
        typer.echo("Invalid configuration. Check environment settings.", err=True)
        raise typer.Exit(1) from None
    typer.echo("Configuration valid.")
