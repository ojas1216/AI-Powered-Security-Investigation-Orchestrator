"""Executive intelligence API: board-level SOC summary.

Read-only aggregation across the tenant's investigations. Tenant-isolated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.executive import build_executive_engine
from app.repository import get_repo
from app.schemas.executive import ExecutiveSummary

router = APIRouter()
_engine = build_executive_engine()

_MAX_INCIDENTS = 5000


@router.get("/summary", response_model=ExecutiveSummary)
async def executive_summary(
    window_days: int = Query(default=30, ge=1, le=365),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> ExecutiveSummary:
    packages = get_repo().list(principal.tenant, limit=_MAX_INCIDENTS)
    return _engine.summarize(packages, window_days=window_days)
