"""Investigation package: the analyst-facing output."""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, Severity, Verdict
from app.schemas.ioc import EnrichedIOC


class TimelineEvent(BaseModel):
    timestamp: datetime
    actor: str | None = None
    action: str
    detail: str | None = None
    source: str | None = None


class MitreTechnique(BaseModel):
    technique_id: str  # e.g. T1566.002
    name: str
    tactic: str


class Evidence(BaseModel):
    kind: str  # sandbox_report | edr_telemetry | email_artifact | screenshot | ti_result
    label: str
    sha256: str  # content hash → tamper evidence
    uri: str  # location in evidence store
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskBreakdown(BaseModel):
    score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    factors: dict[str, float] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


class PlaybookStep(BaseModel):
    phase: str  # containment | eradication | recovery | detection
    action: str
    rationale: str
    requires_approval: bool = True


class TicketRef(BaseModel):
    system: str  # servicenow | jira
    ticket_id: str
    url: str | None = None


class InvestigationPackage(BaseModel):
    investigation_id: str
    tenant: str
    status: InvestigationStatus
    alert: Alert
    overall_verdict: Verdict = Verdict.UNKNOWN
    risk: RiskBreakdown | None = None
    iocs: list[EnrichedIOC] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    mitre: list[MitreTechnique] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    playbook: list[PlaybookStep] = Field(default_factory=list)
    tickets: list[TicketRef] = Field(default_factory=list)
    executive_summary: str = ""
    analyst_report: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
