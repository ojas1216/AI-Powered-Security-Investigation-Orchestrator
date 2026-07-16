"""Alert ingestion → run investigation (sync) or queue it (async, 202)."""
from __future__ import annotations

import base64
import binascii
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.ingestion.normalizers import get_normalizer
from app.ingestion.parsers import ParseError, parse_artifact, supported_extensions
from app.orchestrator import run_investigation
from app.orchestrator.dispatch import CapacityError, get_dispatcher
from app.repository import get_repo
from app.schemas.alert import RawAlert
from app.schemas.common import SourceProduct
from app.schemas.investigation import InvestigationPackage

router = APIRouter()
log = get_logger("api.alerts")

_MAX_ARTIFACT_BYTES = 10 * 1024 * 1024  # 10 MiB upload cap


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
    from app.core.metrics import registry

    registry().inc("aegis_alerts_ingested_total", mode=mode)

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


class ArtifactIngestRequest(BaseModel):
    """Upload an artifact as UTF-8 `content` or base64 `content_b64` (binary)."""

    filename: str = Field(min_length=1, max_length=512)
    content: str | None = Field(default=None, max_length=20_000_000)
    content_b64: str | None = Field(default=None, max_length=27_000_000)


@router.post("/ingest-file", response_model=None, status_code=201)
async def ingest_file(
    body: ArtifactIngestRequest,
    response: Response,
    mode: Literal["sync", "async"] = "sync",
    principal: Principal = Depends(require(Permission.ALERT_INGEST)),
) -> InvestigationPackage | QueuedInvestigation:
    """Parse an uploaded artifact (.eml / Windows-event .xml|.json / .csv / .txt)
    into an alert and investigate it. `content` for text, `content_b64` for
    binary; size-capped at 10 MiB."""
    if body.content_b64:
        try:
            raw = base64.b64decode(body.content_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=422,
                                detail=f"invalid base64: {exc}") from exc
    elif body.content is not None:
        raw = body.content.encode("utf-8")
    else:
        raise HTTPException(status_code=422,
                            detail="provide 'content' or 'content_b64'")
    if len(raw) > _MAX_ARTIFACT_BYTES:
        raise HTTPException(status_code=413, detail="artifact exceeds 10 MiB")

    try:
        alert = parse_artifact(body.filename, raw)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    log.info("artifact_ingested", tenant=principal.tenant, filename=body.filename,
             actor=principal.username, mode=mode, bytes=len(raw))
    from app.core.metrics import registry

    registry().inc("aegis_alerts_ingested_total", mode=f"file:{mode}")

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


@router.get("/artifact-types", response_model=list[str])
async def artifact_types(
    principal: Principal = Depends(require(Permission.ALERT_INGEST)),
) -> list[str]:
    """Supported uploadable artifact extensions."""
    return supported_extensions()
