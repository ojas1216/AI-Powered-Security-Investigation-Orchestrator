"""Incident DNA API: fetch an incident's fingerprints and find similar incidents.

Complements case-memory recall and semantic search with typed, per-dimension
similarity (infrastructure vs malware vs TTP vs identity). Tenant-isolated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.fingerprint import (
    build_fingerprint_engine,
    build_fingerprint_store,
)
from app.schemas.investigation import FingerprintMatch, IncidentDNA

router = APIRouter()
_engine = build_fingerprint_engine()
_store = build_fingerprint_store()


@router.get("/{investigation_id}", response_model=IncidentDNA)
async def get_dna(
    investigation_id: str,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> IncidentDNA:
    dna = _store.get(principal.tenant, investigation_id)
    if dna is None:
        raise HTTPException(status_code=404, detail="no fingerprint for that incident")
    return dna


@router.get("/{investigation_id}/matches", response_model=list[FingerprintMatch])
async def get_matches(
    investigation_id: str,
    limit: int = Query(default=5, ge=1, le=50),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[FingerprintMatch]:
    dna = _store.get(principal.tenant, investigation_id)
    if dna is None:
        raise HTTPException(status_code=404, detail="no fingerprint for that incident")
    priors = _store.all_for_tenant(principal.tenant)
    return _engine.match(dna, priors, limit=limit)
