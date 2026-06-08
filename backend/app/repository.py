"""Investigation repository.

Two interchangeable implementations behind one interface:
- InMemoryInvestigationRepo: tenant-partitioned dict, zero dependencies (default).
- PostgresInvestigationRepo: SQLAlchemy + Postgres Row-Level Security. Isolation is
  enforced by the database itself (the per-transaction `app.tenant_id` GUC), with an
  application-level tenant filter as belt-and-suspenders.

Select the backend with AEGIS_PERSISTENCE = memory | postgres.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Protocol

from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.schemas.investigation import InvestigationPackage


class InvestigationRepo(Protocol):
    def save(self, pkg: InvestigationPackage) -> None: ...
    def get(self, tenant: str, investigation_id: str) -> InvestigationPackage: ...
    def list(self, tenant: str, limit: int = 50) -> list[InvestigationPackage]: ...


class InMemoryInvestigationRepo:
    def __init__(self) -> None:
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


class PostgresInvestigationRepo:
    """Persists packages to Postgres; isolation enforced by RLS + tenant filter."""

    def save(self, pkg: InvestigationPackage) -> None:
        from app.db.models import AlertRecord, InvestigationRecord, IOCRecord
        from app.db.session import tenant_session

        with tenant_session() as session:
            alert = AlertRecord(
                tenant_id=pkg.tenant,
                source=pkg.alert.source.value,
                source_alert_id=pkg.alert.source_alert_id,
                title=pkg.alert.title,
                severity=pkg.alert.severity.value,
                payload=pkg.alert.model_dump(mode="json"),
            )
            session.add(alert)
            session.flush()  # populate alert.id
            session.add(
                InvestigationRecord(
                    id=pkg.investigation_id,
                    tenant_id=pkg.tenant,
                    alert_id=alert.id,
                    status=pkg.status.value,
                    overall_verdict=pkg.overall_verdict.value,
                    risk_score=pkg.risk.score if pkg.risk else 0.0,
                    package=pkg.model_dump(mode="json"),
                )
            )
            for e in pkg.iocs:
                session.add(
                    IOCRecord(
                        tenant_id=pkg.tenant,
                        investigation_id=pkg.investigation_id,
                        type=e.ioc.type.value,
                        value=e.ioc.value,
                        verdict=e.verdict.value,
                        confidence=e.confidence,
                    )
                )

    def get(self, tenant: str, investigation_id: str) -> InvestigationPackage:
        from app.db.models import InvestigationRecord
        from app.db.session import tenant_session

        with tenant_session() as session:
            # RLS already constrains to the current tenant; the explicit filter is
            # defense in depth (and documents intent).
            rec = (
                session.query(InvestigationRecord)
                .filter(
                    InvestigationRecord.id == investigation_id,
                    InvestigationRecord.tenant_id == tenant,
                )
                .one_or_none()
            )
            if rec is None:
                raise NotFoundError("Investigation not found")
            return InvestigationPackage.model_validate(rec.package)

    def list(self, tenant: str, limit: int = 50) -> list[InvestigationPackage]:
        from app.db.models import InvestigationRecord
        from app.db.session import tenant_session

        with tenant_session() as session:
            rows = (
                session.query(InvestigationRecord)
                .filter(InvestigationRecord.tenant_id == tenant)
                .order_by(InvestigationRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [InvestigationPackage.model_validate(r.package) for r in rows]


@lru_cache
def get_repo() -> InvestigationRepo:
    if settings.use_postgres:
        return PostgresInvestigationRepo()
    return InMemoryInvestigationRepo()
