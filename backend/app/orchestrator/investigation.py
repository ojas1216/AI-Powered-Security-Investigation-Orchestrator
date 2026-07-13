"""The Investigation Orchestrator.

Thin composition root: builds every engine, binds them into the agent Toolbox,
and delegates to the AutonomousInvestigator (plan -> act -> observe -> re-plan ->
finalize; see app/agents/loop.py). This module stays transport-agnostic: it runs
in-process for dev/tests, and the same entrypoint is wrapped as a Temporal
activity in `temporal_workflow.py` for durable production execution.
"""
from __future__ import annotations

from app.agents import AutonomousInvestigator, build_case_memory
from app.agents.tools import Toolbox
from app.engines.copilot import build_copilot
from app.engines.edr import build_edr
from app.engines.email_investigation import build_email
from app.engines.evidence import build_evidence_store
from app.engines.graph import build_graph
from app.engines.sandbox import build_sandbox
from app.engines.threat_intel import build_aggregator
from app.engines.ticketing import build_ticketing
from app.schemas.alert import Alert
from app.schemas.investigation import InvestigationPackage


class InvestigationOrchestrator:
    def __init__(self) -> None:
        toolbox = Toolbox(
            ti=build_aggregator(),
            sandbox=build_sandbox(),
            edr=build_edr(),
            email=build_email(),
            evidence=build_evidence_store(),
            copilot=build_copilot(),
            ticketing=build_ticketing(),
        )
        self.agent = AutonomousInvestigator(
            toolbox=toolbox,
            graph=build_graph(),
            memory=build_case_memory(),
        )

    async def investigate(self, tenant: str, alert: Alert) -> InvestigationPackage:
        return await self.agent.investigate(tenant, alert)


_orchestrator: InvestigationOrchestrator | None = None


async def run_investigation(tenant: str, alert: Alert) -> InvestigationPackage:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = InvestigationOrchestrator()
    return await _orchestrator.investigate(tenant, alert)
