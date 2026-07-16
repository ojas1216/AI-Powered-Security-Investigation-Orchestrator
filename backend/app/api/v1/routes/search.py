"""Natural-language case search.

Semantic search over completed investigations: "credential phishing hitting
finance", "ransomware shadow-copy deletion", etc. Complements the exact
IOC-overlap recall — this is fuzzy and language-based. Tenant-isolated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.semantic import CaseSearchHit, build_case_index

router = APIRouter()
log = get_logger("api.search")

_index = build_case_index()


class CaseSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2048)
    limit: int = Field(default=5, ge=1, le=50)


@router.post("/cases", response_model=list[CaseSearchHit])
async def search_cases(
    body: CaseSearchRequest,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[CaseSearchHit]:
    hits = _index.search(principal.tenant, body.query, limit=body.limit)
    log.info("case_search", tenant=principal.tenant, actor=principal.username,
             results=len(hits))
    return hits
