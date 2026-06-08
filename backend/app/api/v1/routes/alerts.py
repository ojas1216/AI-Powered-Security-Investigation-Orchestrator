"""Alert ingestion → run investigation → return package."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.ingestion.normalizers import get_normalizer
from app.orchestrator import run_investigation
from app.repository import repo
from app.schemas.alert import RawAlert
from app.schemas.common import SourceProduct
from app.schemas.investigation import InvestigationPackage

router = APIRouter()
log = get_logger("api.alerts")


@router.post("/ingest", response_model=InvestigationPackage, status_code=201)
async def ingest_alert(
    raw: RawAlert,
    principal: Principal = Depends(require(Permission.ALERT_INGEST)),
) -> InvestigationPackage:
    """Ingest a raw SIEM alert, normalize it, and run a full investigation.

    The source is taken from the payload's `source` field and routed to the right
    normalizer. In production this enqueues a Temporal workflow and returns 202 with
    the investigation id; here we run synchronously and return the package.
    """
    payload = raw.model_dump()
    source = SourceProduct(payload.get("source", "generic"))
    alert = get_normalizer(source).normalize(payload)
    log.info("alert_ingested", tenant=principal.tenant, source=source.value,
             alert_id=alert.source_alert_id, actor=principal.username)
    pkg = await run_investigation(principal.tenant, alert)
    repo.save(pkg)
    return pkg
