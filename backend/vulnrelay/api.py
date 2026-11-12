import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from vulnrelay import __version__
from vulnrelay.config import get_settings
from vulnrelay.db import create_database_engine
from vulnrelay.http_limits import BodyLimitMiddleware
from vulnrelay.operations import readiness
from vulnrelay.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.engine = create_database_engine(get_settings().database_url)
    yield
    app.state.engine.dispose()


app = FastAPI(title="VulnRelay", version=__version__, lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
app.add_middleware(BodyLimitMiddleware)
app.include_router(router)


@app.middleware("http")
async def local_security(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        token = get_settings().api_token.get_secret_value()
        if token and not secrets.compare_digest(
            request.headers.get("authorization", "").encode("utf-8"), f"Bearer {token}".encode()
        ):
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if request.headers.get("x-vulnrelay-request") != "1":
                return JSONResponse({"detail": "Required request header missing"}, status_code=403)
            if origin:
                try:
                    parsed = urlsplit(origin)
                except ValueError:
                    return JSONResponse({"detail": "Invalid Origin"}, status_code=403)
                if (
                    parsed.netloc != request.headers.get("host")
                    or parsed.scheme != request.url.scheme
                ):
                    return JSONResponse({"detail": "Cross-origin mutation denied"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
    return response


@app.get("/health")
def health(request: Request):
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok", "database": "reachable"}


@app.get("/ready")
def ready(request: Request):
    try:
        return readiness(request.app.state.engine)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(
            status_code=503, detail="Database schema is not ready; run vulnrelay init"
        ) from exc


ui_directory = Path(get_settings().ui_dir)
if ui_directory.is_dir():
    app.mount("/", StaticFiles(directory=ui_directory, html=True), name="ui")
