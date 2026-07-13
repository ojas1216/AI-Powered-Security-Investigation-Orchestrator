"""Human-approval workflow contracts.

Playbook actions are never auto-executed (see SECURITY.md, AI security). Each
actionable step becomes an ApprovalRequest that a privileged human must decide;
execution is a separate, audited transition. The full lifecycle is:

    PENDING ──approve──▶ APPROVED ──mark executed──▶ EXECUTED
       │──reject──▶ REJECTED
       │──(TTL elapses)──▶ EXPIRED
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.schemas.investigation import PlaybookStep


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    approval_id: str
    tenant: str
    investigation_id: str
    step: PlaybookStep
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_by: str  # "aegisflow-agent" for loop-created requests
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_note: str | None = Field(default=None, max_length=2048)
    executed_by: str | None = None
    executed_at: datetime | None = None
    execution_note: str | None = Field(default=None, max_length=2048)


class ApprovalDecision(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2048)


class ExecutionReport(BaseModel):
    note: str = Field(default="", max_length=2048)
