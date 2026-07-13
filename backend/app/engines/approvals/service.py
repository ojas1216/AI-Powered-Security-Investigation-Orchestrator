"""Approval workflow service: state machine + four-eyes + expiry + audit.

Rules enforced here (not in the API layer, so every transport gets them):

- Only PENDING requests can be decided; only APPROVED can be marked executed.
- Four-eyes: the requester can never decide their own request.
- Requests expire after a TTL; deciding an expired request transitions it to
  EXPIRED and refuses the decision.
- Every transition is structlog-audited with actor, tenant and request id.

The store is process-local and tenant-partitioned (swappable-backend pattern;
production persists to Postgres with RLS and emits events to Kafka).
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app.core.logging import get_logger
from app.schemas.approval import ApprovalRequest, ApprovalStatus
from app.schemas.investigation import InvestigationPackage

log = get_logger("approvals")

DEFAULT_TTL = timedelta(hours=72)


class ApprovalError(Exception):
    """Invalid transition or rule violation; maps to 409 at the API."""


class ApprovalNotFound(Exception):
    """Unknown approval id within this tenant; maps to 404 at the API."""


class ApprovalService:
    def __init__(self, *, ttl: timedelta = DEFAULT_TTL,
                 now_fn: Callable[[], datetime] | None = None) -> None:
        self._lock = threading.Lock()
        self._by_tenant: dict[str, dict[str, ApprovalRequest]] = {}
        self._ttl = ttl
        self._now = now_fn or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------- create

    def create_for_package(self, pkg: InvestigationPackage,
                           requested_by: str = "aegisflow-agent",
                           ) -> list[ApprovalRequest]:
        """One approval request per playbook step that requires approval."""
        now = self._now()
        requests = [
            ApprovalRequest(
                approval_id=str(uuid.uuid4()),
                tenant=pkg.tenant,
                investigation_id=pkg.investigation_id,
                step=step,
                requested_by=requested_by,
                requested_at=now,
                expires_at=now + self._ttl,
            )
            for step in pkg.playbook if step.requires_approval
        ]
        with self._lock:
            bucket = self._by_tenant.setdefault(pkg.tenant, {})
            for req in requests:
                bucket[req.approval_id] = req
        for req in requests:
            log.info("approval_requested", approval_id=req.approval_id,
                     tenant=req.tenant, investigation_id=req.investigation_id,
                     action=req.step.action, requested_by=requested_by)
        return requests

    # ------------------------------------------------------------- read

    def get(self, tenant: str, approval_id: str) -> ApprovalRequest:
        with self._lock:
            req = self._by_tenant.get(tenant, {}).get(approval_id)
        if req is None:
            raise ApprovalNotFound(approval_id)
        return self._expire_if_due(req)

    def list(self, tenant: str, status: ApprovalStatus | None = None,
             investigation_id: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            items = list(self._by_tenant.get(tenant, {}).values())
        items = [self._expire_if_due(r) for r in items]
        if status is not None:
            items = [r for r in items if r.status is status]
        if investigation_id is not None:
            items = [r for r in items if r.investigation_id == investigation_id]
        items.sort(key=lambda r: r.requested_at, reverse=True)
        return items

    # ------------------------------------------------------------- transitions

    def decide(self, tenant: str, approval_id: str, *, actor: str,
               approve: bool, note: str = "") -> ApprovalRequest:
        with self._lock:
            req = self._by_tenant.get(tenant, {}).get(approval_id)
            if req is None:
                raise ApprovalNotFound(approval_id)
            self._expire_if_due_locked(req)
            if req.status is not ApprovalStatus.PENDING:
                raise ApprovalError(
                    f"cannot decide a request in state '{req.status.value}'")
            if actor == req.requested_by:
                raise ApprovalError(
                    "four-eyes violation: requester cannot decide their own request")
            req.status = (ApprovalStatus.APPROVED if approve
                          else ApprovalStatus.REJECTED)
            req.decided_by = actor
            req.decided_at = self._now()
            req.decision_note = note or None
        log.info("approval_decided", approval_id=approval_id, tenant=tenant,
                 actor=actor, decision=req.status.value, note=note)
        return req

    def mark_executed(self, tenant: str, approval_id: str, *, actor: str,
                      note: str = "") -> ApprovalRequest:
        with self._lock:
            req = self._by_tenant.get(tenant, {}).get(approval_id)
            if req is None:
                raise ApprovalNotFound(approval_id)
            if req.status is not ApprovalStatus.APPROVED:
                raise ApprovalError(
                    f"only approved actions can be executed "
                    f"(state is '{req.status.value}')")
            req.status = ApprovalStatus.EXECUTED
            req.executed_by = actor
            req.executed_at = self._now()
            req.execution_note = note or None
        log.info("approval_executed", approval_id=approval_id, tenant=tenant,
                 actor=actor, action=req.step.action, note=note)
        return req

    # ------------------------------------------------------------- expiry

    def _expire_if_due(self, req: ApprovalRequest) -> ApprovalRequest:
        with self._lock:
            self._expire_if_due_locked(req)
        return req

    def _expire_if_due_locked(self, req: ApprovalRequest) -> None:
        if req.status is ApprovalStatus.PENDING and self._now() >= req.expires_at:
            req.status = ApprovalStatus.EXPIRED
            log.info("approval_expired", approval_id=req.approval_id,
                     tenant=req.tenant)


_service: ApprovalService | None = None


def build_approval_service() -> ApprovalService:
    global _service
    if _service is None:
        _service = ApprovalService()
    return _service
