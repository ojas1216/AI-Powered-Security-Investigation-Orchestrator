"""OpenTelemetry spans + Prometheus metrics.

Metrics are always available: the /metrics endpoint renders our zero-dependency
registry (app/core/metrics.py) so it works air-gapped and in tests. OTel tracing
is best-effort — spans are emitted through the SDK when it is installed, and the
`span()` context manager degrades to a no-op otherwise, so the agent loop can be
instrumented unconditionally.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from app.core.logging import get_logger
from app.core.metrics import registry

log = get_logger("otel")

try:
    from opentelemetry import trace as _otel_trace

    _tracer = _otel_trace.get_tracer("aegisflow")
except Exception:  # pragma: no cover - optional dep
    _tracer = None


@contextmanager
def span(name: str, **attributes) -> Iterator[None]:
    """Start an OTel span if tracing is available; else a no-op context."""
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as s:  # pragma: no cover - needs SDK
        for k, v in attributes.items():
            s.set_attribute(k, v)
        yield


def setup_observability(app, service_name: str = "aegisflow-api") -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
        log.info("otel_instrumented", service=service_name)
    except Exception as exc:  # pragma: no cover - optional dep
        log.info("otel_skipped", reason=str(exc))


async def _metrics_app(scope, receive, send) -> None:
    """Minimal ASGI app rendering the metrics registry as Prometheus text."""
    body = registry().render().encode()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain; version=0.0.4; charset=utf-8")],
    })
    await send({"type": "http.response.body", "body": body})


def metrics_asgi_app():
    """Always-available Prometheus exposition ASGI app (no client lib needed)."""
    return _metrics_app
