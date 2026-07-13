"""Investigation package: the analyst-facing output."""
from __future__ import annotations

from datetime import UTC, datetime

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
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


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


class DetectionMatch(BaseModel):
    """A detection rule that fired on the ingested alert."""

    rule_id: str
    title: str
    severity: Severity
    techniques: list[MitreTechnique] = Field(default_factory=list)
    matched_fields: dict[str, str] = Field(default_factory=dict)  # field -> excerpt
    tags: list[str] = Field(default_factory=list)


class AgentTraceStep(BaseModel):
    """One explainable step of the autonomous investigation loop.

    The full trace answers: what did the agent do, in what order, *why*, and
    what did each action observe — the audit trail regulators and analysts ask for.
    """

    step: int
    iteration: int
    phase: str  # plan | act | observe | finalize
    action: str
    reason: str
    outcome: str = ""
    ok: bool = True
    duration_ms: float = 0.0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RelatedCase(BaseModel):
    """A past investigation recalled from long-term memory as similar to this one."""

    investigation_id: str
    title: str
    verdict: Verdict
    risk_score: float = 0.0
    similarity: float = Field(ge=0.0, le=1.0)
    shared_iocs: list[str] = Field(default_factory=list)
    shared_techniques: list[str] = Field(default_factory=list)


class InvestigationPackage(BaseModel):
    investigation_id: str
    tenant: str
    status: InvestigationStatus
    alert: Alert
    overall_verdict: Verdict = Verdict.UNKNOWN
    risk: RiskBreakdown | None = None
    iocs: list[EnrichedIOC] = Field(default_factory=list)
    detections: list[DetectionMatch] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    mitre: list[MitreTechnique] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    playbook: list[PlaybookStep] = Field(default_factory=list)
    # Approval requests raised for playbook steps (fetch via /approvals API).
    approval_ids: list[str] = Field(default_factory=list)
    tickets: list[TicketRef] = Field(default_factory=list)
    executive_summary: str = ""
    analyst_report: str = ""
    agent_trace: list[AgentTraceStep] = Field(default_factory=list)
    related_investigations: list[RelatedCase] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
