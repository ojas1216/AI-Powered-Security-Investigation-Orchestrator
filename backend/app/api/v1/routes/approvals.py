"""Human-approval workflow API.

Deciding (approve/reject) and marking-executed require `investigation:act` —
the containment permission — while any investigation reader can list requests.
State-machine and four-eyes violations surface as 409, unknown ids as 404.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal
from app.engines.approvals import (
    ApprovalError,
    ApprovalNotFound,
    build_approval_service,
)
from app.schemas.approval import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ExecutionReport,
)

router = APIRouter()
log = get_logger("api.approvals")

_service = build_approval_service()


@router.get("", response_model=list[ApprovalRequest])
async def list_approvals(
    status: ApprovalStatus | None = None,
    investigation_id: str | None = None,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[ApprovalRequest]:
    return _service.list(principal.tenant, status=status,
                         investigation_id=investigation_id)


@router.get("/{approval_id}", response_model=ApprovalRequest)
async def get_approval(
    approval_id: str,
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> ApprovalRequest:
    try:
        return _service.get(principal.tenant, approval_id)
    except ApprovalNotFound as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc


@router.post("/{approval_id}/decision", response_model=ApprovalRequest)
async def decide_approval(
    approval_id: str,
    body: ApprovalDecision,
    principal: Principal = Depends(require(Permission.INVESTIGATION_ACT)),
) -> ApprovalRequest:
    try:
        return _service.decide(
            principal.tenant, approval_id,
            actor=principal.username, approve=body.approve, note=body.note)
    except ApprovalNotFound as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{approval_id}/executed", response_model=ApprovalRequest)
async def mark_executed(
    approval_id: str,
    body: ExecutionReport,
    principal: Principal = Depends(require(Permission.INVESTIGATION_ACT)),
) -> ApprovalRequest:
    try:
        return _service.mark_executed(
            principal.tenant, approval_id,
            actor=principal.username, note=body.note)
    except ApprovalNotFound as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
