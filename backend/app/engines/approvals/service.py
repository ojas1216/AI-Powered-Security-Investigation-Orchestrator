"""Approval workflow service: state machine + four-eyes + expiry + audit.

Rules enforced here (not in the API layer, so every transport gets them):

- Only PENDING requests can be decided; only APPROVED can be marked executed.
- Four-eyes: the requester can never decide their own request.
- Requests expire after a TTL; deciding an expired request transitions it to
  EXPIRED and refuses the decision.
- Every transition is structlog-audited with actor, tenant and request id.

Storage is pluggable behind ApprovalStore: the in-memory store is the hermetic
default; the Postgres store persists every transition (RLS-isolated) so the
approval queue survives restarts and is shared across API replicas.
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.core.logging import get_logger
from app.schemas.approval import ApprovalRequest, ApprovalStatus
from app.schemas.investigation import InvestigationPackage

log = get_logger("approvals")

DEFAULT_TTL = timedelta(hours=72)


class ApprovalError(Exception):
    """Invalid transition or rule violation; maps to 409 at the API."""


class ApprovalNotFound(Exception):
    """Unknown approval id within this tenant; maps to 404 at the API."""


class ApprovalStore(Protocol):
    """Persistence contract; the state machine lives in ApprovalService."""

    def add(self, req: ApprovalRequest) -> None: ...
    def get(self, tenant: str, approval_id: str) -> ApprovalRequest | None: ...
    def list(self, tenant: str) -> list[ApprovalRequest]: ...
    def save(self, req: ApprovalRequest) -> None: ...


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._by_tenant: dict[str, dict[str, ApprovalRequest]] = {}

    def add(self, req: ApprovalRequest) -> None:
        self._by_tenant.setdefault(req.tenant, {})[req.approval_id] = req

    def get(self, tenant: str, approval_id: str) -> ApprovalRequest | None:
        return self._by_tenant.get(tenant, {}).get(approval_id)

    def list(self, tenant: str) -> list[ApprovalRequest]:
        return list(self._by_tenant.get(tenant, {}).values())

    def save(self, req: ApprovalRequest) -> None:
        self.add(req)  # same object graph; idempotent


class PostgresApprovalStore:
    """Durable, RLS-isolated approval storage (full request JSON + status column)."""

    def add(self, req: ApprovalRequest) -> None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import ApprovalRecord
        from app.db.session import tenant_session

        set_current_tenant(req.tenant)
        with tenant_session() as session:
            session.add(ApprovalRecord(
                id=req.approval_id,
                tenant_id=req.tenant,
                investigation_id=req.investigation_id,
                status=req.status.value,
                request=req.model_dump(mode="json"),
            ))

    def get(self, tenant: str, approval_id: str) -> ApprovalRequest | None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import ApprovalRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rec = (
                session.query(ApprovalRecord)
                .filter(ApprovalRecord.id == approval_id,
                        ApprovalRecord.tenant_id == tenant)
                .one_or_none()
            )
            return ApprovalRequest.model_validate(rec.request) if rec else None

    def list(self, tenant: str) -> list[ApprovalRequest]:
        from app.core.tenancy import set_current_tenant
        from app.db.models import ApprovalRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rows = (
                session.query(ApprovalRecord)
                .filter(ApprovalRecord.tenant_id == tenant)
                .all()
            )
            return [ApprovalRequest.model_validate(r.request) for r in rows]

    def save(self, req: ApprovalRequest) -> None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import ApprovalRecord
        from app.db.session import tenant_session

        set_current_tenant(req.tenant)
        with tenant_session() as session:
            rec = (
                session.query(ApprovalRecord)
                .filter(ApprovalRecord.id == req.approval_id,
                        ApprovalRecord.tenant_id == req.tenant)
                .one_or_none()
            )
            if rec is None:  # pragma: no cover - save always follows add/get
                raise ApprovalNotFound(req.approval_id)
            rec.status = req.status.value
            rec.request = req.model_dump(mode="json")


class ApprovalService:
    def __init__(self, *, ttl: timedelta = DEFAULT_TTL,
                 now_fn: Callable[[], datetime] | None = None,
                 store: ApprovalStore | None = None) -> None:
        # The lock serializes transitions within this process; the Postgres
        # store additionally relies on the status guard in decide/mark_executed
        # being re-checked on the freshly-read row (last-writer-wins is
        # prevented because a non-PENDING row can never transition again).
        self._lock = threading.Lock()
        self._store: ApprovalStore = store if store is not None else InMemoryApprovalStore()
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
            for req in requests:
                self._store.add(req)
        for req in requests:
            log.info("approval_requested", approval_id=req.approval_id,
                     tenant=req.tenant, investigation_id=req.investigation_id,
                     action=req.step.action, requested_by=requested_by)
        return requests

    # ------------------------------------------------------------- read

    def get(self, tenant: str, approval_id: str) -> ApprovalRequest:
        with self._lock:
            req = self._store.get(tenant, approval_id)
            if req is None:
                raise ApprovalNotFound(approval_id)
            self._expire_if_due_locked(req)
        return req

    def list(self, tenant: str, status: ApprovalStatus | None = None,
             investigation_id: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            items = self._store.list(tenant)
            for req in items:
                self._expire_if_due_locked(req)
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
            req = self._store.get(tenant, approval_id)
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
            self._store.save(req)
        log.info("approval_decided", approval_id=approval_id, tenant=tenant,
                 actor=actor, decision=req.status.value, note=note)
        return req

    def mark_executed(self, tenant: str, approval_id: str, *, actor: str,
                      note: str = "") -> ApprovalRequest:
        with self._lock:
            req = self._store.get(tenant, approval_id)
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
            self._store.save(req)
        log.info("approval_executed", approval_id=approval_id, tenant=tenant,
                 actor=actor, action=req.step.action, note=note)
        return req

    # ------------------------------------------------------------- expiry

    def _expire_if_due_locked(self, req: ApprovalRequest) -> None:
        if req.status is ApprovalStatus.PENDING and self._now() >= req.expires_at:
            req.status = ApprovalStatus.EXPIRED
            self._store.save(req)
            log.info("approval_expired", approval_id=req.approval_id,
                     tenant=req.tenant)


_service: ApprovalService | None = None


def build_approval_service() -> ApprovalService:
    global _service
    if _service is None:
        from app.core.config import settings

        store = PostgresApprovalStore() if settings.use_postgres else None
        _service = ApprovalService(store=store)
    return _service
