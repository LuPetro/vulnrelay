from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from sqlalchemy import text

from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.engine = create_database_engine(get_settings().database_url)
    yield
    app.state.engine.dispose()


app = FastAPI(title="VulnRelay", version="0.1.0a0", lifespan=lifespan)


@app.get("/health")
def health(request: Request):
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok", "database": "reachable"}
