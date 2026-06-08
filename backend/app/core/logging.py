"""Structured, tenant-aware JSON logging.

Secrets must never be logged. The processor below redacts a configurable set of
sensitive keys defensively even if a caller passes them through.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_SENSITIVE_KEYS = {
    "password",
    "token",
    "api_key",
    "secret",
    "authorization",
    "jwt",
    "refresh_token",
}


def _redact(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = "***REDACTED***"
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=getattr(logging, level.upper(), 20)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _redact,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), 20)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "aegisflow") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
