"""Threat-intelligence dossier API.

Generates a complete intelligence dossier for a single indicator — the
enterprise-grade replacement for a shallow reputation lookup. Tenant-isolated;
offline-first (works with zero credentials).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.threat_intel.dossier import build_dossier_engine
from app.schemas.intel import ThreatIntelligenceDossier

router = APIRouter()
log = get_logger("api.intel")

_engine = build_dossier_engine()


class DossierRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


@router.post("/dossier", response_model=ThreatIntelligenceDossier)
async def dossier(
    body: DossierRequest,
    principal: Principal = Depends(require(Permission.IOC_READ)),
) -> ThreatIntelligenceDossier:
    indicator = body.indicator.strip()
    if not indicator:
        raise HTTPException(status_code=422, detail="empty indicator")
    log.info("dossier_requested", tenant=principal.tenant, actor=principal.username)
    return await _engine.build(indicator, principal.tenant)
