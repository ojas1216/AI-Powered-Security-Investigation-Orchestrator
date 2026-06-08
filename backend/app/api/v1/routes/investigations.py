"""Read investigations. Every read is tenant-gated (anti-IDOR)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import require
from app.core.authz import Permission, ResourceContext, abac_check
from app.core.security import Principal
from app.repository import get_repo
from app.schemas.investigation import InvestigationPackage

router = APIRouter()


@router.get("", response_model=list[InvestigationPackage])
async def list_investigations(
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[InvestigationPackage]:
    return get_repo().list(principal.tenant)


@router.get("/{investigation_id}", response_model=InvestigationPackage)
async def get_investigation(
    investigation_id: str,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> InvestigationPackage:
    pkg = get_repo().get(principal.tenant, investigation_id)
    # ABAC: tenant match + asset sensitivity gate.
    sensitivity = "crown_jewel" if any(
        "FIN" in h.upper() for h in pkg.affected_hosts) else "standard"
    abac_check(principal, ResourceContext(tenant=pkg.tenant, sensitivity=sensitivity))
    return pkg
