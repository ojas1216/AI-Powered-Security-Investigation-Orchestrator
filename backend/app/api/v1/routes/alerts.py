"""Alert ingestion → run investigation (sync) or queue it (async, 202)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.ingestion.normalizers import get_normalizer
from app.orchestrator import run_investigation
from app.orchestrator.dispatch import CapacityError, get_dispatcher
from app.repository import get_repo
from app.schemas.alert import RawAlert
from app.schemas.common import SourceProduct
from app.schemas.investigation import InvestigationPackage

router = APIRouter()
log = get_logger("api.alerts")


class QueuedInvestigation(BaseModel):
    investigation_id: str
    status: str = "queued"


@router.post("/ingest", response_model=None, status_code=201)
async def ingest_alert(
    raw: RawAlert,
    response: Response,
    mode: Literal["sync", "async"] = "sync",
    principal: Principal = Depends(require(Permission.ALERT_INGEST)),
) -> InvestigationPackage | QueuedInvestigation:
    """Ingest a raw SIEM alert, normalize it, and investigate.

    `mode=sync` (default) runs the investigation and returns the full package
    with 201 — convenient for analysts and tests. `mode=async` queues it and
    returns 202 immediately with the investigation id — the production shape
    for alert storms; poll GET /investigations/{id}. At capacity the async
    path returns 429 so the SIEM forwarder backs off instead of piling on.
    """
    payload = raw.model_dump()
    source = SourceProduct(payload.get("source", "generic"))
    alert = get_normalizer(source).normalize(payload)
    log.info("alert_ingested", tenant=principal.tenant, source=source.value,
             alert_id=alert.source_alert_id, actor=principal.username, mode=mode)

    if mode == "async":
        try:
            investigation_id = await get_dispatcher().submit(principal.tenant, alert)
        except CapacityError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        response.status_code = 202
        return QueuedInvestigation(investigation_id=investigation_id)

    pkg = await run_investigation(principal.tenant, alert)
    get_repo().save(pkg)
    return pkg
