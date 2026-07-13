"""The autonomous investigation loop: plan -> act -> observe -> re-plan -> finalize.

Replaces a hardcoded pipeline with a budgeted agent loop:

  1. The Planner reads the InvestigationState and proposes the next batch of
     independent actions (with reasons).
  2. The loop executes the batch concurrently via the ToolRegistry; each tool
     folds observations back into the state.
  3. Repeat until the planner has nothing left or a budget trips.
  4. Finalize: timeline fusion, graph write, MITRE mapping, risk scoring,
     memory recall of similar past cases, copilot narrative, playbook, ticket —
     then commit the case to long-term memory.

Every decision and observation is captured as an AgentTraceStep in the package,
so the investigation is fully explainable after the fact. A tool failure is
recorded and investigation continues on partial evidence — availability of the
pipeline never depends on any single connector.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from app.agents.memory import CaseMemory
from app.agents.planner import Budget, PlannedAction, Planner
from app.agents.state import InvestigationState
from app.agents.tools import Toolbox
from app.core.logging import get_logger
from app.engines.graph.client import GraphClient, GraphTriple
from app.engines.mitre import map_techniques
from app.engines.playbook import recommend_playbook
from app.engines.risk_scoring import score_investigation
from app.engines.risk_scoring.scorer import RiskInputs
from app.engines.timeline import build_timeline
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, Verdict
from app.schemas.investigation import AgentTraceStep, InvestigationPackage
from app.schemas.ioc import EnrichedIOC

log = get_logger("agents.loop")


class AutonomousInvestigator:
    def __init__(self, *, toolbox: Toolbox, graph: GraphClient, memory: CaseMemory,
                 planner: Planner | None = None, budget: Budget | None = None) -> None:
        self.toolbox = toolbox
        self.graph = graph
        self.memory = memory
        self.planner = planner or Planner()
        self.budget = budget or Budget()

    async def investigate(self, tenant: str, alert: Alert) -> InvestigationPackage:
        inv_id = str(uuid.uuid4())
        log.info("investigation_start", investigation_id=inv_id, tenant=tenant,
                 alert=alert.source_alert_id)
        pkg = InvestigationPackage(
            investigation_id=inv_id, tenant=tenant,
            status=InvestigationStatus.RUNNING, alert=alert,
        )
        state = InvestigationState(
            tenant=tenant, alert=alert,
            text_corpus="\n".join([alert.raw_text, alert.title, alert.description]),
            signals=[alert.raw_text, alert.title, alert.description],
        )
        trace: list[AgentTraceStep] = []
        started = time.monotonic()
        step_no = 0
        tool_calls = 0

        for iteration in range(1, self.budget.max_iterations + 1):
            elapsed = time.monotonic() - started
            if elapsed > self.budget.max_wall_clock_seconds:
                step_no += 1
                trace.append(AgentTraceStep(
                    step=step_no, iteration=iteration, phase="plan",
                    action="stop", ok=False,
                    reason=f"wall-clock budget exhausted after {elapsed:.1f}s",
                    outcome="finalizing on partial evidence"))
                break

            actions = self.planner.next_actions(state)
            if not actions:
                break  # evidence collection converged

            if tool_calls + len(actions) > self.budget.max_tool_calls:
                actions = actions[: max(0, self.budget.max_tool_calls - tool_calls)]
                if not actions:
                    step_no += 1
                    trace.append(AgentTraceStep(
                        step=step_no, iteration=iteration, phase="plan",
                        action="stop", ok=False,
                        reason="tool-call budget exhausted",
                        outcome="finalizing on partial evidence"))
                    break

            results = await asyncio.gather(
                *(self._run_tool(state, a) for a in actions))
            tool_calls += len(actions)
            for action, (ok, outcome, duration_ms, started_at) in zip(
                    actions, results, strict=True):
                step_no += 1
                trace.append(AgentTraceStep(
                    step=step_no, iteration=iteration, phase="act",
                    action=action.tool, reason=action.reason, outcome=outcome,
                    ok=ok, duration_ms=duration_ms, started_at=started_at))

        await self._finalize(pkg, state, trace, step_no)
        log.info("investigation_complete", investigation_id=inv_id,
                 verdict=pkg.overall_verdict.value,
                 risk=pkg.risk.score if pkg.risk else None,
                 trace_steps=len(pkg.agent_trace), tool_calls=tool_calls)
        return pkg

    async def _run_tool(
        self, state: InvestigationState, action: PlannedAction,
    ) -> tuple[bool, str, float, datetime]:
        started_at = datetime.now(UTC)
        t0 = time.monotonic()
        try:
            spec = self.toolbox.registry.get(action.tool)
            outcome = await spec.fn(state, **action.params)
            return True, outcome, (time.monotonic() - t0) * 1000, started_at
        except Exception as exc:  # noqa: BLE001 - single tool failure must not kill the case
            log.warning("tool_failed", tool=action.tool, error=str(exc))
            state.errors.append(f"{action.tool}: {exc}")
            return False, f"error: {exc}", (time.monotonic() - t0) * 1000, started_at

    async def _finalize(self, pkg: InvestigationPackage, state: InvestigationState,
                        trace: list[AgentTraceStep], step_no: int) -> None:
        def note(action: str, reason: str, outcome: str) -> None:
            nonlocal step_no
            step_no += 1
            trace.append(AgentTraceStep(
                step=step_no, iteration=0, phase="finalize",
                action=action, reason=reason, outcome=outcome))

        pkg.iocs = list(state.enriched.values())
        pkg.affected_hosts = sorted({h.host for h in state.edr_hits})
        pkg.affected_users = sorted(state.affected_users)
        pkg.timeline = build_timeline(*state.timeline_groups)
        pkg.evidence = state.evidence
        self._write_graph(pkg)

        has_mal_url = any(
            e.ioc.type.value == "url" and e.verdict is Verdict.MALICIOUS
            for e in pkg.iocs)
        pkg.mitre = map_techniques(state.signals, has_malicious_url=has_mal_url)
        note("map_mitre", "Tag observed behaviors with ATT&CK techniques",
             f"{len(pkg.mitre)} techniques")

        pkg.risk = score_investigation(RiskInputs(
            enriched_iocs=pkg.iocs,
            sandbox_malscore=state.sandbox_malscore,
            edr_confirmed_hits=len(state.edr_hits),
            mitre=pkg.mitre,
            asset_criticality=_asset_criticality(pkg.affected_hosts),
            recipient_count=len(pkg.affected_users),
        ))
        pkg.overall_verdict = _overall_verdict(pkg.iocs, pkg.risk.score)
        note("score_risk", "Fuse TI/sandbox/EDR/ATT&CK/asset factors into 0-100 risk",
             f"risk={pkg.risk.score:.0f} verdict={pkg.overall_verdict.value}")

        pkg.related_investigations = self.memory.recall(
            pkg.tenant,
            {e.ioc.key() for e in pkg.iocs},
            {t.technique_id for t in pkg.mitre},
        )
        note("recall_memory", "Search long-term memory for prior related campaigns",
             f"{len(pkg.related_investigations)} related past investigations")

        pkg.executive_summary = await self.toolbox.copilot.executive_summary(pkg)
        pkg.analyst_report = await self.toolbox.copilot.analyst_report(pkg)
        note("draft_report", "Copilot drafts grounded exec + analyst narratives",
             f"{len(pkg.analyst_report)} chars")

        pkg.playbook = recommend_playbook(pkg.mitre, pkg.overall_verdict)
        if pkg.overall_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            try:
                ticket = await self.toolbox.ticketing.create_ticket(pkg)
                pkg.tickets = [ticket]
                note("open_ticket", "Actionable verdict requires a tracked response",
                     f"{ticket.system}:{ticket.ticket_id}")
            except Exception as exc:  # noqa: BLE001 - ticketing outage must not fail the case
                log.warning("ticketing_failed", error=str(exc))
                note("open_ticket", "Actionable verdict requires a tracked response",
                     f"error: {exc}")

        pkg.status = InvestigationStatus.COMPLETE
        pkg.completed_at = datetime.now(UTC)
        pkg.agent_trace = trace
        self.memory.remember(pkg)

    def _write_graph(self, pkg: InvestigationPackage) -> None:
        alert_node = f"alert:{pkg.alert.source_alert_id}"
        triples = [GraphTriple(alert_node, "contains", e.ioc.key()) for e in pkg.iocs]
        triples += [GraphTriple(f"host:{h}", "affected_by", alert_node)
                    for h in pkg.affected_hosts]
        triples += [GraphTriple(f"user:{u}", "received", alert_node)
                    for u in pkg.affected_users]
        if triples:
            self.graph.upsert(pkg.tenant, triples)


def _overall_verdict(iocs: list[EnrichedIOC], risk_score: float) -> Verdict:
    if any(e.verdict is Verdict.MALICIOUS for e in iocs) or risk_score >= 70:
        return Verdict.MALICIOUS
    if any(e.verdict is Verdict.SUSPICIOUS for e in iocs) or risk_score >= 35:
        return Verdict.SUSPICIOUS
    if iocs:
        return Verdict.BENIGN
    return Verdict.UNKNOWN


def _asset_criticality(hosts: list[str]) -> float:
    # Hosts in the finance segment are treated as high-criticality (demo heuristic;
    # production reads from a CMDB/asset inventory).
    if any("FIN" in h.upper() for h in hosts):
        return 0.9
    return 0.5 if hosts else 0.3
