"""Per-request tenant context (the backbone of multi-tenant isolation).

The context var is set by middleware/deps and read by the DB session to apply
Postgres Row-Level Security (`SET app.tenant_id = ...`) and by cache/graph layers
to prefix keys/labels.
"""
from __future__ import annotations

import contextvars
import re
from dataclasses import dataclass

from app.core.exceptions import ValidationFailure

_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")

_current_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_tenant", default=None
)


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str


def validate_tenant_id(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if not _TENANT_RE.match(raw):
        raise ValidationFailure("Invalid tenant id")
    return raw


def set_current_tenant(tenant_id: str) -> None:
    _current_tenant.set(validate_tenant_id(tenant_id))


def get_current_tenant() -> str:
    tenant = _current_tenant.get()
    if not tenant:
        raise ValidationFailure("No tenant in context")
    return tenant


def reset_tenant() -> None:
    _current_tenant.set(None)
