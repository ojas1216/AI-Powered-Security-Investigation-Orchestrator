"""OpenTelemetry + Prometheus wiring (best-effort, no-op if libs absent).

Kept import-light so the app runs in minimal/offline environments. In the full
stack, the OTel SDK is installed and exports traces to the collector.
"""
from __future__ import annotations

from app.core.logging import get_logger

log = get_logger("otel")


def setup_observability(app, service_name: str = "aegisflow-api") -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
        log.info("otel_instrumented", service=service_name)
    except Exception as exc:  # pragma: no cover - optional dep
        log.info("otel_skipped", reason=str(exc))


def metrics_asgi_app():
    """Return a Prometheus ASGI app if the client lib is installed, else None."""
    try:
        from prometheus_client import make_asgi_app

        return make_asgi_app()
    except Exception:  # pragma: no cover - optional dep
        return None
