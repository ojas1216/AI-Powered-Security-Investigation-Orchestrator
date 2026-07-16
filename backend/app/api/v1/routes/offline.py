"""Offline knowledge-base API: ATT&CK / CVE / Sigma.

All lookups are served from the bundled seed (or a refreshed cache) so they work
fully air-gapped. Refresh pulls the upstream source when online and is gated to
detection engineers/admins.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.detection.rules import DetectionRule
from app.engines.offline_cache import (
    AttackTechnique,
    CveRecord,
    DatasetStatus,
    build_offline_datasets,
)

router = APIRouter()
log = get_logger("api.offline")

_datasets = build_offline_datasets()


@router.get("/status", response_model=list[DatasetStatus])
async def status(
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> list[DatasetStatus]:
    return _datasets.statuses()


@router.get("/attack/{technique_id}", response_model=AttackTechnique)
async def attack_technique(
    technique_id: str,
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> AttackTechnique:
    tech = _datasets.attack.get(technique_id)
    if tech is None:
        raise HTTPException(status_code=404, detail="technique not in offline set")
    return tech


@router.get("/cve/{cve_id}", response_model=CveRecord)
async def cve(
    cve_id: str,
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> CveRecord:
    record = _datasets.cve.get(cve_id)
    if record is None:
        raise HTTPException(status_code=404, detail="CVE not in offline set")
    return record


@router.get("/sigma", response_model=list[DetectionRule])
async def sigma_rules(
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> list[DetectionRule]:
    """The bundled Sigma pack, converted to the platform's DetectionRule DSL."""
    return _datasets.sigma.as_detection_rules()


@router.post("/refresh/{dataset}")
async def refresh(
    dataset: str,
    principal: Principal = Depends(require(Permission.DETECTION_WRITE)),
) -> dict:
    """Sync a dataset from its upstream source (requires connectivity)."""
    try:
        cache = _datasets.by_name(dataset)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        count = await cache.refresh()
    except Exception as exc:  # noqa: BLE001 - surface refresh failure as 502
        raise HTTPException(
            status_code=502, detail=f"refresh failed: {exc}") from exc
    log.info("dataset_refreshed_api", dataset=dataset, actor=principal.username)
    return {"dataset": dataset, "records": count, "status": "refreshed"}
