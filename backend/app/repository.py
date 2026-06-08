"""Investigation repository.

Production persists to Postgres (with RLS) via app.db. For the self-contained
runtime we keep a tenant-partitioned in-memory store so the API works without a
database. The interface is identical so swapping in the DB-backed implementation
is a one-line change in the route dependencies.
"""
from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.schemas.investigation import InvestigationPackage


class InMemoryInvestigationRepo:
    def __init__(self) -> None:
        # tenant -> {investigation_id -> package}
        self._store: dict[str, dict[str, InvestigationPackage]] = {}

    def save(self, pkg: InvestigationPackage) -> None:
        self._store.setdefault(pkg.tenant, {})[pkg.investigation_id] = pkg

    def get(self, tenant: str, investigation_id: str) -> InvestigationPackage:
        # Tenant gate first — never serve another tenant's object (anti-IDOR).
        pkg = self._store.get(tenant, {}).get(investigation_id)
        if pkg is None:
            raise NotFoundError("Investigation not found")
        return pkg

    def list(self, tenant: str, limit: int = 50) -> list[InvestigationPackage]:
        items = list(self._store.get(tenant, {}).values())
        items.sort(key=lambda p: p.created_at, reverse=True)
        return items[:limit]


repo = InMemoryInvestigationRepo()
