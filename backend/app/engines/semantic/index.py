"""Case index: embed completed investigations and search them in natural language.

This is the semantic complement to the exact IOC-overlap recall in
`agents/memory.py`. Overlap recall answers "does this share indicators with a
past case" (deterministic, explainable, drives `related_investigations`). The
semantic index answers "find cases *about* credential phishing against finance"
— fuzzy, natural-language, over the whole case text. Both are tenant-isolated.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.engines.semantic.embedder import Embedder, build_embedder
from app.engines.semantic.store import VectorRecord, VectorStore, build_vector_store
from app.schemas.investigation import InvestigationPackage

log = get_logger("semantic.index")

_SNIPPET_LEN = 240


class CaseSearchHit(BaseModel):
    investigation_id: str
    title: str
    verdict: str
    risk_score: float = 0.0
    score: float = Field(ge=-1.0, le=1.0)
    snippet: str = ""


def case_text(pkg: InvestigationPackage) -> str:
    """The searchable projection of a case: alert + indicators + techniques +
    hosts/users + the copilot's executive summary."""
    parts = [
        pkg.alert.title,
        pkg.alert.description,
        pkg.alert.raw_text,
        pkg.overall_verdict.value,
        " ".join(e.ioc.value for e in pkg.iocs),
        " ".join(t.name for t in pkg.mitre),
        " ".join(t.technique_id for t in pkg.mitre),
        " ".join(pkg.affected_hosts),
        " ".join(pkg.affected_users),
        pkg.executive_summary,
    ]
    return "\n".join(p for p in parts if p)


class CaseIndex:
    def __init__(self, embedder: Embedder, store: VectorStore) -> None:
        self._embedder = embedder
        self._store = store

    def index_package(self, pkg: InvestigationPackage) -> None:
        text = case_text(pkg)
        record = VectorRecord(
            id=pkg.investigation_id,
            tenant=pkg.tenant,
            text=text,
            vector=self._embedder.embed(text),
            metadata={
                "title": pkg.alert.title,
                "verdict": pkg.overall_verdict.value,
                "risk_score": pkg.risk.score if pkg.risk else 0.0,
            },
        )
        self._store.add(record)
        log.info("case_indexed", investigation_id=pkg.investigation_id,
                 tenant=pkg.tenant)

    def search(self, tenant: str, query: str, limit: int = 5,
               min_score: float = 0.05) -> list[CaseSearchHit]:
        if not query.strip():
            return []
        qvec = self._embedder.embed(query)
        hits: list[CaseSearchHit] = []
        for scored in self._store.search(tenant, qvec, limit=limit):
            if scored.score < min_score:
                continue
            r = scored.record
            hits.append(CaseSearchHit(
                investigation_id=r.id,
                title=str(r.metadata.get("title", "")),
                verdict=str(r.metadata.get("verdict", "unknown")),
                risk_score=float(r.metadata.get("risk_score", 0.0)),
                score=round(scored.score, 4),
                snippet=r.text[:_SNIPPET_LEN].replace("\n", " "),
            ))
        return hits


_index: CaseIndex | None = None


def build_case_index() -> CaseIndex:
    global _index
    if _index is None:
        _index = CaseIndex(build_embedder(), build_vector_store())
    return _index
