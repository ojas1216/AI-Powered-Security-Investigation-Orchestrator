"""AegisFlow API entrypoint.

Wires middleware (CORS, security headers, request-id), exception mapping, the v1
router, and observability. Refuses to boot with the auth dev-bypass enabled outside
a local environment — a fail-closed guard against accidental prod exposure.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import AegisError
from app.core.logging import configure_logging, get_logger
from app.core.observability import metrics_asgi_app, setup_observability

configure_logging(settings.log_level)
log = get_logger("app")

if settings.auth_dev_bypass and not settings.is_local:
    raise RuntimeError(
        "AEGIS_AUTH_DEV_BYPASS must not be enabled outside a local environment"
    )

app = FastAPI(
    title="AegisFlow API",
    version=__version__,
    description="AI-Powered Security Investigation Orchestrator",
    docs_url="/docs" if settings.is_local else None,  # no Swagger in prod
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID", "X-Roles"],
)


@app.middleware("http")
async def security_and_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    # Hardened response headers (defense in depth alongside the gateway/WAF).
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(AegisError)
async def aegis_error_handler(_: Request, exc: AegisError) -> JSONResponse:
    # Map typed errors to safe responses; never leak internals to the client.
    return JSONResponse(
        status_code=exc.status,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


app.include_router(api_router, prefix="/api/v1")
setup_observability(app)

_metrics = metrics_asgi_app()
if _metrics is not None:
    app.mount("/metrics", _metrics)


@app.get("/")
async def root() -> dict:
    return {"service": "aegisflow", "version": __version__, "docs": "/docs"}


log.info("app_started", env=settings.env, connector_mode=settings.connector_mode.value)
