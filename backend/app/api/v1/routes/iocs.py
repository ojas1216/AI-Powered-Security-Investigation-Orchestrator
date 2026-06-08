"""Ad-hoc IOC extraction + enrichment (analyst pivot)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.ioc_extraction import extract_iocs
from app.engines.threat_intel import build_aggregator
from app.schemas.ioc import EnrichedIOC

router = APIRouter()
_aggregator = build_aggregator()


class ExtractRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    enrich: bool = True


@router.post("/extract", response_model=list[EnrichedIOC])
async def extract_and_enrich(
    body: ExtractRequest,
    principal: Principal = Depends(require(Permission.IOC_READ)),
) -> list[EnrichedIOC]:
    iocs = extract_iocs(body.text)
    if not body.enrich:
        return [EnrichedIOC(ioc=i) for i in iocs]
    return await _aggregator.enrich_many(iocs)
