"""Campaign detection API: cluster correlated incidents into campaigns.

Clusters the tenant's persisted investigations by shared attacker DNA and
attaches a threat-actor-type attribution to each campaign. Tenant-isolated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.campaign import build_campaign_engine
from app.repository import get_repo
from app.schemas.investigation import CampaignCluster

router = APIRouter()
_engine = build_campaign_engine()

_MAX_INCIDENTS = 2000


@router.get("", response_model=list[CampaignCluster])
async def list_campaigns(
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[CampaignCluster]:
    packages = get_repo().list(principal.tenant, limit=_MAX_INCIDENTS)
    return _engine.cluster(packages)[:limit]


@router.get("/for/{investigation_id}", response_model=CampaignCluster)
async def campaign_for_incident(
    investigation_id: str,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> CampaignCluster:
    packages = get_repo().list(principal.tenant, limit=_MAX_INCIDENTS)
    cluster = _engine.cluster_for(investigation_id, packages)
    if cluster is None:
        raise HTTPException(
            status_code=404,
            detail="incident is not part of a detected campaign")
    return cluster
