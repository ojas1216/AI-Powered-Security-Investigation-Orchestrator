"""Persistence models. Every tenant-scoped table carries tenant_id and is
protected by a Postgres Row-Level Security policy (see alembic migration)."""
from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TenantMixin, TimestampMixin, _uuid


class AlertRecord(Base, TenantMixin, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String(32))
    source_alert_id: Mapped[str] = mapped_column(String(256), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class InvestigationRecord(Base, TenantMixin, TimestampMixin):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    overall_verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    package: Mapped[dict] = mapped_column(JSON, default=dict)

    iocs: Mapped[list[IOCRecord]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class IOCRecord(Base, TenantMixin, TimestampMixin):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), index=True
    )
    type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    investigation: Mapped[InvestigationRecord] = relationship(back_populates="iocs")


class AuditLog(Base, TenantMixin, TimestampMixin):
    """Tamper-evident audit trail. Append-only by convention + DB grants."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="success")
    detail: Mapped[str] = mapped_column(Text, default="")


class CaseMemoryRecord(Base, TenantMixin, TimestampMixin):
    """Compact long-term memory of a completed investigation (agent recall)."""

    __tablename__ = "case_memory"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    title: Mapped[str] = mapped_column(String(512))
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    ioc_keys: Mapped[list] = mapped_column(JSON, default=list)
    technique_ids: Mapped[list] = mapped_column(JSON, default=list)


class ApprovalRecord(Base, TenantMixin, TimestampMixin):
    """Human-approval request for a playbook action (full lifecycle state)."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # approval_id
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    request: Mapped[dict] = mapped_column(JSON, default=dict)  # full ApprovalRequest


class DetectionRuleRecord(Base, TenantMixin, TimestampMixin):
    """Tenant-authored detection rule (validated DetectionRule JSON)."""

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule: Mapped[dict] = mapped_column(JSON, default=dict)


class UserAccountRecord(Base, TenantMixin, TimestampMixin):
    """Native/Google user account. Looked up globally at sign-in (no RLS),
    tenant-scoped everywhere else."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(256), default="")
    roles: Mapped[list] = mapped_column(JSON, default=list)
    provider: Mapped[str] = mapped_column(String(16), default="password")
    password_hash: Mapped[str] = mapped_column(String(256), default="")
