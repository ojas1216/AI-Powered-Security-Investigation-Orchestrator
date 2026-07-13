"""Threat hunting: pivot on arbitrary indicators across TI, EDR and case memory.

One request answers the hunter's three questions at once:
  1. What does threat intel say about these indicators?  (enrichment)
  2. Did any host in my estate touch them?               (EDR hunt)
  3. Have we seen this campaign before?                  (long-term case memory)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.memory import build_case_memory
from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.edr import build_edr
from app.engines.edr.base import EDRHit
from app.engines.ioc_extraction import extract_iocs
from app.engines.threat_intel import build_aggregator
from app.schemas.investigation import RelatedCase
from app.schemas.ioc import EnrichedIOC

router = APIRouter()
log = get_logger("api.hunts")

_aggregator = build_aggregator()
_edr = build_edr()
_memory = build_case_memory()


class HuntRequest(BaseModel):
    """Free text (IOCs are extracted, defang-aware) and/or explicit indicators."""

    text: str = Field(default="", max_length=200_000)
    indicators: list[str] = Field(default_factory=list, max_length=256)


class HuntResult(BaseModel):
    iocs: list[EnrichedIOC]
    edr_hits: list[EDRHit]
    affected_hosts: list[str]
    related_investigations: list[RelatedCase]


@router.post("", response_model=HuntResult)
async def run_hunt(
    body: HuntRequest,
    principal: Principal = Depends(require(Permission.HUNT_RUN)),
) -> HuntResult:
    corpus = body.text + "\n" + "\n".join(body.indicators)
    iocs = extract_iocs(corpus)
    if not iocs:
        raise HTTPException(status_code=422, detail="no valid indicators found")

    enriched = await _aggregator.enrich_many(iocs)
    hits = await _edr.hunt(iocs)
    related = _memory.recall(
        principal.tenant, {i.key() for i in iocs}, set())

    log.info("hunt_executed", tenant=principal.tenant, actor=principal.username,
             iocs=len(iocs), edr_hits=len(hits), related=len(related))
    return HuntResult(
        iocs=enriched,
        edr_hits=hits,
        affected_hosts=sorted({h.host for h in hits}),
        related_investigations=related,
    )
