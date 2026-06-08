"""Typed application exceptions mapped to HTTP responses in main.py."""
from __future__ import annotations


class AegisError(Exception):
    """Base class. `status` drives the HTTP response code."""

    status = 500
    code = "internal_error"

    def __init__(self, message: str = "Internal error") -> None:
        super().__init__(message)
        self.message = message


class AuthError(AegisError):
    status = 401
    code = "unauthenticated"


class ForbiddenError(AegisError):
    status = 403
    code = "forbidden"


class NotFoundError(AegisError):
    status = 404
    code = "not_found"


class ValidationFailure(AegisError):
    status = 422
    code = "validation_error"


class RateLimitError(AegisError):
    status = 429
    code = "rate_limited"


class SsrfBlockedError(ForbiddenError):
    code = "ssrf_blocked"


class ConnectorError(AegisError):
    status = 502
    code = "connector_error"
