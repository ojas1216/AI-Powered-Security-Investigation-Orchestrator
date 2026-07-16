"""Incident-DNA store: persist fingerprints so future incidents compare to them.

Tenant-partitioned. In-memory by default (hermetic); Postgres-backed when
AEGIS_PERSISTENCE=postgres (RLS-isolated), mirroring the case-memory pattern.
"""
from __future__ import annotations

import abc
import threading

from app.core.logging import get_logger
from app.schemas.investigation import IncidentDNA

log = get_logger("fingerprint.store")


class FingerprintStore(abc.ABC):
    @abc.abstractmethod
    def store(self, tenant: str, dna: IncidentDNA, title: str) -> None: ...

    @abc.abstractmethod
    def all_for_tenant(self, tenant: str, limit: int = 2000,
                       ) -> list[tuple[IncidentDNA, str]]: ...

    @abc.abstractmethod
    def get(self, tenant: str, investigation_id: str) -> IncidentDNA | None: ...


class InMemoryFingerprintStore(FingerprintStore):
    def __init__(self, max_per_tenant: int = 20_000) -> None:
        self._lock = threading.Lock()
        self._by_tenant: dict[str, dict[str, tuple[IncidentDNA, str]]] = {}
        self._max = max_per_tenant

    def store(self, tenant: str, dna: IncidentDNA, title: str) -> None:
        with self._lock:
            bucket = self._by_tenant.setdefault(tenant, {})
            bucket[dna.investigation_id] = (dna, title)
            if len(bucket) > self._max:  # FIFO eviction keeps memory bounded
                del bucket[next(iter(bucket))]

    def all_for_tenant(self, tenant: str, limit: int = 2000,
                       ) -> list[tuple[IncidentDNA, str]]:
        with self._lock:
            return list(self._by_tenant.get(tenant, {}).values())[-limit:]

    def get(self, tenant: str, investigation_id: str) -> IncidentDNA | None:
        with self._lock:
            row = self._by_tenant.get(tenant, {}).get(investigation_id)
            return row[0] if row else None


class PostgresFingerprintStore(FingerprintStore):
    def store(self, tenant: str, dna: IncidentDNA, title: str) -> None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import IncidentDNARecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            existing = (
                session.query(IncidentDNARecord)
                .filter(IncidentDNARecord.tenant_id == tenant,
                        IncidentDNARecord.investigation_id == dna.investigation_id)
                .one_or_none()
            )
            if existing is not None:
                existing.dna = dna.model_dump(mode="json")
                existing.title = title
            else:
                session.add(IncidentDNARecord(
                    tenant_id=tenant, investigation_id=dna.investigation_id,
                    title=title, dna=dna.model_dump(mode="json")))

    def all_for_tenant(self, tenant: str, limit: int = 2000,
                       ) -> list[tuple[IncidentDNA, str]]:
        from app.core.tenancy import set_current_tenant
        from app.db.models import IncidentDNARecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rows = (
                session.query(IncidentDNARecord)
                .filter(IncidentDNARecord.tenant_id == tenant)
                .order_by(IncidentDNARecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [(IncidentDNA.model_validate(r.dna), r.title) for r in rows]

    def get(self, tenant: str, investigation_id: str) -> IncidentDNA | None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import IncidentDNARecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rec = (
                session.query(IncidentDNARecord)
                .filter(IncidentDNARecord.tenant_id == tenant,
                        IncidentDNARecord.investigation_id == investigation_id)
                .one_or_none()
            )
            return IncidentDNA.model_validate(rec.dna) if rec else None


_store: FingerprintStore | None = None


def build_fingerprint_store() -> FingerprintStore:
    global _store
    if _store is None:
        from app.core.config import settings

        _store = (PostgresFingerprintStore() if settings.use_postgres
                  else InMemoryFingerprintStore())
    return _store
