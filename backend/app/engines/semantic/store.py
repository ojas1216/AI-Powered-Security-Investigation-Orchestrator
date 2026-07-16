"""Vector store — tenant-partitioned similarity search.

The default `InMemoryVectorStore` does exact brute-force cosine search (fine to
tens of thousands of cases/tenant; the embeddings are tiny). It is the hermetic,
offline default. A production deployment swaps in a real vector DB (ChromaDB is
already in the stack) behind the same interface; per-tenant partitioning and the
cosine ranking contract are unchanged.
"""
from __future__ import annotations

import abc
import threading
from dataclasses import dataclass, field

from app.engines.semantic.embedder import cosine


@dataclass
class VectorRecord:
    id: str
    tenant: str
    text: str
    vector: list[float]
    metadata: dict = field(default_factory=dict)


@dataclass
class ScoredRecord:
    record: VectorRecord
    score: float


class VectorStore(abc.ABC):
    @abc.abstractmethod
    def add(self, record: VectorRecord) -> None: ...

    @abc.abstractmethod
    def search(self, tenant: str, query: list[float], limit: int = 5,
               ) -> list[ScoredRecord]: ...


class InMemoryVectorStore(VectorStore):
    def __init__(self, max_per_tenant: int = 50_000) -> None:
        self._lock = threading.Lock()
        self._by_tenant: dict[str, dict[str, VectorRecord]] = {}
        self._max = max_per_tenant

    def add(self, record: VectorRecord) -> None:
        with self._lock:
            bucket = self._by_tenant.setdefault(record.tenant, {})
            bucket[record.id] = record  # upsert by id (re-index is idempotent)
            if len(bucket) > self._max:  # FIFO-ish eviction keeps memory bounded
                oldest = next(iter(bucket))
                del bucket[oldest]

    def search(self, tenant: str, query: list[float], limit: int = 5,
               ) -> list[ScoredRecord]:
        with self._lock:
            records = list(self._by_tenant.get(tenant, {}).values())
        scored = [ScoredRecord(r, cosine(query, r.vector)) for r in records]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:limit]


_store: VectorStore | None = None


def build_vector_store() -> VectorStore:
    global _store
    if _store is None:
        _store = InMemoryVectorStore()
    return _store
