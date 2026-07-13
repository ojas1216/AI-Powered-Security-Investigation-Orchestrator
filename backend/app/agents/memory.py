"""Long-term investigation memory.

After every completed investigation the agent remembers a compact case record
(IOC keys, ATT&CK techniques, verdict, risk). Before finalizing a new case it
recalls tenant-scoped similar cases so the analyst sees "this campaign hit us
before" without hunting for it — and so the copilot can ground its narrative in
prior incidents.

Similarity is deliberately transparent (weighted IOC / technique overlap), not
an embedding black box: the shared indicators are returned with the recall so
the match is verifiable. The store is swappable (protocol) like every other
backend in this codebase; the in-memory implementation is process-local and the
Postgres-backed one persists across restarts.
"""
from __future__ import annotations

import abc
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.logging import get_logger
from app.schemas.common import Verdict
from app.schemas.investigation import InvestigationPackage, RelatedCase

log = get_logger("agents.memory")

# IOC overlap dominates: shared infrastructure is far stronger evidence of the
# same campaign than shared (often generic) techniques.
_IOC_WEIGHT = 0.7
_TECH_WEIGHT = 0.3
_MIN_SIMILARITY = 0.05


@dataclass
class CaseRecord:
    investigation_id: str
    tenant: str
    title: str
    verdict: Verdict
    risk_score: float
    ioc_keys: frozenset[str]
    technique_ids: frozenset[str]
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _overlap(a: frozenset[str], b: frozenset[str]) -> tuple[float, list[str]]:
    if not a or not b:
        return 0.0, []
    shared = a & b
    return len(shared) / min(len(a), len(b)), sorted(shared)


def similarity(candidate: CaseRecord, ioc_keys: frozenset[str],
               technique_ids: frozenset[str]) -> RelatedCase | None:
    ioc_score, shared_iocs = _overlap(candidate.ioc_keys, ioc_keys)
    tech_score, shared_techs = _overlap(candidate.technique_ids, technique_ids)
    score = _IOC_WEIGHT * ioc_score + _TECH_WEIGHT * tech_score
    # Technique overlap alone (no shared indicator) is not a campaign match.
    if score < _MIN_SIMILARITY or not shared_iocs:
        return None
    return RelatedCase(
        investigation_id=candidate.investigation_id,
        title=candidate.title,
        verdict=candidate.verdict,
        risk_score=candidate.risk_score,
        similarity=round(min(score, 1.0), 4),
        shared_iocs=shared_iocs,
        shared_techniques=shared_techs,
    )


class CaseMemory(abc.ABC):
    @abc.abstractmethod
    def remember(self, pkg: InvestigationPackage) -> None:
        """Store a compact record of a completed investigation."""

    @abc.abstractmethod
    def recall(self, tenant: str, ioc_keys: set[str], technique_ids: set[str],
               limit: int = 5) -> list[RelatedCase]:
        """Return tenant-scoped similar past cases, most similar first."""


class InMemoryCaseMemory(CaseMemory):
    """Thread-safe, tenant-partitioned, bounded process-local memory."""

    def __init__(self, max_cases_per_tenant: int = 5000) -> None:
        self._lock = threading.Lock()
        self._by_tenant: dict[str, list[CaseRecord]] = {}
        self._max = max_cases_per_tenant

    def remember(self, pkg: InvestigationPackage) -> None:
        record = CaseRecord(
            investigation_id=pkg.investigation_id,
            tenant=pkg.tenant,
            title=pkg.alert.title,
            verdict=pkg.overall_verdict,
            risk_score=pkg.risk.score if pkg.risk else 0.0,
            ioc_keys=frozenset(e.ioc.key() for e in pkg.iocs),
            technique_ids=frozenset(t.technique_id for t in pkg.mitre),
        )
        with self._lock:
            cases = self._by_tenant.setdefault(pkg.tenant, [])
            cases.append(record)
            if len(cases) > self._max:  # FIFO eviction keeps memory bounded
                del cases[: len(cases) - self._max]
        log.info("case_remembered", investigation_id=pkg.investigation_id,
                 tenant=pkg.tenant, iocs=len(record.ioc_keys))

    def recall(self, tenant: str, ioc_keys: set[str], technique_ids: set[str],
               limit: int = 5) -> list[RelatedCase]:
        with self._lock:
            candidates = list(self._by_tenant.get(tenant, ()))
        iocs = frozenset(ioc_keys)
        techs = frozenset(technique_ids)
        matches = [
            m for c in candidates
            if (m := similarity(c, iocs, techs)) is not None
        ]
        matches.sort(key=lambda m: m.similarity, reverse=True)
        return matches[:limit]


class PostgresCaseMemory(CaseMemory):
    """Durable long-term memory (survives restarts; shared across workers).

    Isolation is enforced twice: the explicit tenant filter here, and the
    database's own RLS policy on `case_memory` (per-transaction tenant GUC).
    Candidate scan is capped to the most recent rows so recall stays O(bounded)
    even for tenants with years of history.
    """

    _CANDIDATE_LIMIT = 1000

    def remember(self, pkg: InvestigationPackage) -> None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import CaseMemoryRecord
        from app.db.session import tenant_session

        set_current_tenant(pkg.tenant)  # background workers may lack request ctx
        with tenant_session() as session:
            session.add(CaseMemoryRecord(
                tenant_id=pkg.tenant,
                investigation_id=pkg.investigation_id,
                title=pkg.alert.title,
                verdict=pkg.overall_verdict.value,
                risk_score=pkg.risk.score if pkg.risk else 0.0,
                ioc_keys=sorted(e.ioc.key() for e in pkg.iocs),
                technique_ids=sorted(t.technique_id for t in pkg.mitre),
            ))
        log.info("case_remembered", investigation_id=pkg.investigation_id,
                 tenant=pkg.tenant, backend="postgres")

    def recall(self, tenant: str, ioc_keys: set[str], technique_ids: set[str],
               limit: int = 5) -> list[RelatedCase]:
        from app.core.tenancy import set_current_tenant
        from app.db.models import CaseMemoryRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rows = (
                session.query(CaseMemoryRecord)
                .filter(CaseMemoryRecord.tenant_id == tenant)
                .order_by(CaseMemoryRecord.created_at.desc())
                .limit(self._CANDIDATE_LIMIT)
                .all()
            )
            candidates = [
                CaseRecord(
                    investigation_id=r.investigation_id,
                    tenant=r.tenant_id,
                    title=r.title,
                    verdict=Verdict(r.verdict),
                    risk_score=r.risk_score,
                    ioc_keys=frozenset(r.ioc_keys or ()),
                    technique_ids=frozenset(r.technique_ids or ()),
                )
                for r in rows
            ]
        iocs = frozenset(ioc_keys)
        techs = frozenset(technique_ids)
        matches = [
            m for c in candidates
            if (m := similarity(c, iocs, techs)) is not None
        ]
        matches.sort(key=lambda m: m.similarity, reverse=True)
        return matches[:limit]


_memory: CaseMemory | None = None


def build_case_memory() -> CaseMemory:
    """Process-wide memory singleton (one agent brain per worker)."""
    global _memory
    if _memory is None:
        from app.core.config import settings

        _memory = PostgresCaseMemory() if settings.use_postgres else InMemoryCaseMemory()
    return _memory
