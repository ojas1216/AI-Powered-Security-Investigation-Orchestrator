"""Specialist-agent framework: typed, independently-callable investigation agents."""
from __future__ import annotations

from app.agents.specialists.agents import (
    DetectionAgent,
    EdrHuntAgent,
    EmailAgent,
    IocExtractionAgent,
    MemoryAgent,
    MitreAgent,
    RiskAgent,
    SandboxAgent,
    ThreatIntelAgent,
)
from app.agents.specialists.base import (
    AgentInfo,
    AgentOrchestrator,
    AgentRegistry,
    AgentResult,
    SpecialistAgent,
)
from app.agents.specialists.generation import (
    AttackPathAgent,
    BusinessImpactAgent,
    RootCauseAgent,
    SigmaGeneratorAgent,
    YaraGeneratorAgent,
)

__all__ = [
    "AgentInfo",
    "AgentOrchestrator",
    "AgentRegistry",
    "AgentResult",
    "AttackPathAgent",
    "BusinessImpactAgent",
    "DetectionAgent",
    "EdrHuntAgent",
    "EmailAgent",
    "IocExtractionAgent",
    "MemoryAgent",
    "MitreAgent",
    "RiskAgent",
    "RootCauseAgent",
    "SandboxAgent",
    "SigmaGeneratorAgent",
    "SpecialistAgent",
    "ThreatIntelAgent",
    "YaraGeneratorAgent",
    "build_agent_bundle",
]


class AgentBundle:
    """Holds the concrete specialist instances so the loop's Toolbox and the API
    share exactly one set of agents (single source of truth per capability)."""

    def __init__(
        self,
        *,
        ioc_extraction: IocExtractionAgent,
        threat_intel: ThreatIntelAgent,
        detection: DetectionAgent,
        edr_hunt: EdrHuntAgent,
        sandbox: SandboxAgent,
        email: EmailAgent,
        mitre: MitreAgent,
        risk: RiskAgent,
        memory: MemoryAgent,
        sigma_generator: SigmaGeneratorAgent,
        yara_generator: YaraGeneratorAgent,
        root_cause: RootCauseAgent,
        attack_path: AttackPathAgent,
        business_impact: BusinessImpactAgent,
    ) -> None:
        self.ioc_extraction = ioc_extraction
        self.threat_intel = threat_intel
        self.detection = detection
        self.edr_hunt = edr_hunt
        self.sandbox = sandbox
        self.email = email
        self.mitre = mitre
        self.risk = risk
        self.memory = memory
        self.sigma_generator = sigma_generator
        self.yara_generator = yara_generator
        self.root_cause = root_cause
        self.attack_path = attack_path
        self.business_impact = business_impact

    def registry(self) -> AgentRegistry:
        reg = AgentRegistry()
        for agent in (self.ioc_extraction, self.threat_intel, self.detection,
                      self.edr_hunt, self.sandbox, self.email, self.mitre,
                      self.risk, self.memory, self.sigma_generator,
                      self.yara_generator, self.root_cause, self.attack_path,
                      self.business_impact):
            reg.register(agent)
        return reg

    def orchestrator(self) -> AgentOrchestrator:
        return AgentOrchestrator(self.registry())


def build_agent_bundle() -> AgentBundle:
    """Compose specialists from the standard engine builders."""
    from app.agents.memory import build_case_memory
    from app.engines.detection import build_detection_engine, build_rule_store
    from app.engines.edr import build_edr
    from app.engines.email_investigation import build_email
    from app.engines.graph import build_graph
    from app.engines.sandbox import build_sandbox
    from app.engines.threat_intel import build_aggregator

    return AgentBundle(
        ioc_extraction=IocExtractionAgent(),
        threat_intel=ThreatIntelAgent(build_aggregator()),
        detection=DetectionAgent(build_detection_engine(), build_rule_store()),
        edr_hunt=EdrHuntAgent(build_edr()),
        sandbox=SandboxAgent(build_sandbox()),
        email=EmailAgent(build_email()),
        mitre=MitreAgent(),
        risk=RiskAgent(),
        memory=MemoryAgent(build_case_memory()),
        sigma_generator=SigmaGeneratorAgent(),
        yara_generator=YaraGeneratorAgent(),
        root_cause=RootCauseAgent(),
        attack_path=AttackPathAgent(build_graph()),
        business_impact=BusinessImpactAgent(),
    )


_bundle: AgentBundle | None = None


def get_agent_bundle() -> AgentBundle:
    global _bundle
    if _bundle is None:
        _bundle = build_agent_bundle()
    return _bundle
