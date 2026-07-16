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


class BusinessImpact(BaseModel):
    """Estimated business impact of an investigation (deterministic model)."""

    level: Severity
    blast_radius_hosts: int = 0
    blast_radius_users: int = 0
    affected_asset_classes: list[str] = Field(default_factory=list)
    estimated_cost_band: str = "$0"
    downtime_risk: str = "none"
    rationale: list[str] = Field(default_factory=list)


class RootCause(BaseModel):
    """Reconstructed origin + kill-chain of an investigation."""

    initial_vector: str = "undetermined"
    initial_event: TimelineEvent | None = None
    kill_chain: list[str] = Field(default_factory=list)  # ordered ATT&CK tactics
    narrative: str = ""


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


class Attribution(BaseModel):
    """Estimated threat-actor *type* — never a fabricated named group.

    actor_type: apt | crimeware | ransomware | insider | hacktivist | botnet |
    unattributed. Confidence is explicit and `unattributed` is returned when the
    evidence is not distinctive enough (no fabrication).
    """

    actor_type: str = "unattributed"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)


class CampaignCluster(BaseModel):
    """A cluster of incidents correlated into one campaign by shared DNA."""

    campaign_id: str
    members: list[str] = Field(default_factory=list)  # investigation_ids
    size: int = 0
    shared_infrastructure: list[str] = Field(default_factory=list)
    shared_techniques: list[str] = Field(default_factory=list)
    shared_malware: list[str] = Field(default_factory=list)
    victims: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    verdict: Verdict = Verdict.UNKNOWN
    attribution: Attribution = Field(default_factory=Attribution)


class Fingerprint(BaseModel):
    """One typed fingerprint of an incident.

    `hash` is a stable identity of the feature set (exact-ish matching);
    `features` is the underlying set used for similarity (overlap) comparison.
    """

    kind: str  # infrastructure | malware | ttp | identity | threat | campaign | incident
    hash: str
    features: list[str] = Field(default_factory=list)
    label: str = ""


class IncidentDNA(BaseModel):
    """The multi-dimensional fingerprint of an investigation, stored permanently
    so future incidents can be compared against it."""

    investigation_id: str
    fingerprints: list[Fingerprint] = Field(default_factory=list)

    def by_kind(self, kind: str) -> Fingerprint | None:
        return next((f for f in self.fingerprints if f.kind == kind), None)


class FingerprintMatch(BaseModel):
    """A prior incident that resembles this one, per-dimension."""

    investigation_id: str
    title: str = ""
    overall_similarity: float = Field(ge=0.0, le=1.0)
    dimension_similarity: dict[str, float] = Field(default_factory=dict)
    shared: dict[str, list[str]] = Field(default_factory=dict)


class ConsensusVote(BaseModel):
    """One evidence source's independent vote in the consensus decision."""

    voter: str  # threat_intel | edr | sandbox | detections | mitre
    verdict: Verdict
    malice: float = Field(ge=0.0, le=1.0)  # 0=benign .. 1=malicious
    weight: float = Field(ge=0.0, le=1.0)  # source reliability
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class Hypothesis(BaseModel):
    """An alternative conclusion the consensus weighed, with its probability."""

    verdict: Verdict
    probability: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class ConsensusResult(BaseModel):
    """Explainable multi-voter decision — no single agent decides alone.

    Carries the full reasoning surface required of an explainable decision:
    the votes, the chosen verdict + confidence, ranked alternative hypotheses,
    the supporting and rejected observations, and the reasoning chain.
    """

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    agreement: float = Field(ge=0.0, le=1.0)  # inter-voter agreement
    votes: list[ConsensusVote] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    supporting: list[str] = Field(default_factory=list)
    rejected: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)


class ReflectionFinding(BaseModel):
    """A self-review observation about the investigation's evidence.

    category: coverage (work left undone) | gap (evidence not collected) |
    unverified (a conclusion resting on a single source) | contradiction
    (sources disagree). Residual findings remain after the reflection loop has
    done what it can — they are what an analyst should still scrutinize.
    """

    category: str
    detail: str
    action_recommended: str = ""


class PlanNode(BaseModel):
    """One node of the investigation execution graph (planning layer)."""

    id: str
    tool: str
    reason: str
    status: str  # pending | running | done | failed | skipped
    priority: int = 50
    attempts: int = 0
    depends_on: list[str] = Field(default_factory=list)
    outcome: str = ""
    ok: bool = True
    duration_ms: float = 0.0


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
    business_impact: BusinessImpact | None = None
    root_cause: RootCause | None = None
    plan_graph: list[PlanNode] = Field(default_factory=list)
    reflections: list[ReflectionFinding] = Field(default_factory=list)
    consensus: ConsensusResult | None = None
    incident_dna: IncidentDNA | None = None
    dna_matches: list[FingerprintMatch] = Field(default_factory=list)
    attribution: Attribution | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
