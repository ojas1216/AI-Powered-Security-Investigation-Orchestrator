"""Detection engineering surface: list rules, author tenant rules, dry-run alerts.

The dry-run endpoint is the detection engineer's inner loop: author a rule,
POST a sample alert, see exactly which rules fired and on which fields —
without ingesting anything or opening an investigation.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.detection import (
    BUILTIN_RULES,
    DetectionRule,
    build_detection_engine,
    build_rule_store,
)
from app.engines.detection_export import build_detection_export_engine
from app.ingestion.normalizers import get_normalizer
from app.repository import get_repo
from app.schemas.alert import RawAlert
from app.schemas.common import SourceProduct
from app.schemas.investigation import DetectionMatch, GeneratedRule

router = APIRouter()
log = get_logger("api.detections")

_engine = build_detection_engine()
_store = build_rule_store()
_export = build_detection_export_engine()


class RuleListResponse(BaseModel):
    builtin: list[DetectionRule]
    custom: list[DetectionRule]


@router.get("/rules", response_model=RuleListResponse)
async def list_rules(
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> RuleListResponse:
    return RuleListResponse(
        builtin=list(BUILTIN_RULES),
        custom=_store.list(principal.tenant),
    )


@router.put("/rules", response_model=DetectionRule, status_code=201)
async def upsert_rule(
    rule: DetectionRule,
    principal: Principal = Depends(require(Permission.DETECTION_WRITE)),
) -> DetectionRule:
    """Create or update a tenant-scoped custom rule (validated at the boundary)."""
    try:
        stored = _store.upsert(principal.tenant, rule)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("detection_rule_upserted", tenant=principal.tenant,
             rule_id=rule.id, actor=principal.username)
    return stored


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    principal: Principal = Depends(require(Permission.DETECTION_WRITE)),
) -> None:
    if not _store.delete(principal.tenant, rule_id):
        raise HTTPException(status_code=404, detail="rule not found")
    log.info("detection_rule_deleted", tenant=principal.tenant,
             rule_id=rule_id, actor=principal.username)


@router.post("/evaluate", response_model=list[DetectionMatch])
async def evaluate_alert(
    raw: RawAlert,
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> list[DetectionMatch]:
    """Dry-run: normalize a raw alert and report which rules fire. No side effects."""
    payload = raw.model_dump()
    source = SourceProduct(payload.get("source", "generic"))
    alert = get_normalizer(source).normalize(payload)
    return _engine.evaluate(alert, extra_rules=_store.list(principal.tenant))


@router.get("/export/{investigation_id}", response_model=list[GeneratedRule])
async def export_detections(
    investigation_id: str,
    principal: Principal = Depends(require(Permission.DETECTION_READ)),
) -> list[GeneratedRule]:
    """Generate deployable detections (Sigma/YARA/Suricata/SPL/KQL/YARA-L/EQL/
    Wazuh/Falcon) from an investigation's confirmed indicators, each with
    rationale + estimated precision/recall."""
    pkg = get_repo().get(principal.tenant, investigation_id)  # tenant-gated
    return _export.generate(pkg)
