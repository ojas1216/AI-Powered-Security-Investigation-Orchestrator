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
from app.core.metrics import registry
from app.core.observability import span
from app.engines.approvals import ApprovalService, build_approval_service
from app.engines.graph.client import GraphClient, GraphTriple
from app.engines.mitre import map_techniques
from app.engines.playbook import recommend_playbook
from app.engines.risk_scoring import score_investigation
from app.engines.risk_scoring.scorer import RiskInputs
from app.engines.timeline import build_timeline
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, Verdict
from app.schemas.investigation import AgentTraceStep, InvestigationPackage

log = get_logger("agents.loop")


class AutonomousInvestigator:
    def __init__(self, *, toolbox: Toolbox, graph: GraphClient, memory: CaseMemory,
                 planner: Planner | None = None, budget: Budget | None = None,
                 approvals: ApprovalService | None = None,
                 case_index=None, strategy: str = "batch") -> None:
        self.toolbox = toolbox
        self.graph = graph
        self.memory = memory
        self.planner = planner or Planner()
        self.budget = budget or Budget()
        self.approvals = approvals or build_approval_service()
        # Evidence-collection strategy: "batch" (flat re-plan loop, default) or
        # "taskgraph" (dependency-aware Task Graph + Priority Scheduler with
        # per-task retry/dedup/progress). Both feed the same finalize().
        self.strategy = strategy
        if case_index is None:
            from app.engines.semantic import build_case_index

            case_index = build_case_index()
        self.case_index = case_index

    async def investigate(self, tenant: str, alert: Alert,
                          investigation_id: str | None = None) -> InvestigationPackage:
        inv_id = investigation_id or str(uuid.uuid4())
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

        if self.strategy == "taskgraph":
            step_no, tool_calls = await self._collect_taskgraph(state, pkg, trace)
        else:
            step_no, tool_calls = await self._collect_batch(
                state, trace, started)

        with span("investigation.finalize", investigation_id=inv_id):
            await self.finalize(pkg, state, trace, step_no)

        duration = time.monotonic() - started
        registry().observe("aegis_investigation_duration_seconds", duration)
        registry().inc("aegis_investigations_total",
                       verdict=pkg.overall_verdict.value)
        if state.detections:
            registry().inc("aegis_detections_fired_total", len(state.detections))
        log.info("investigation_complete", investigation_id=inv_id,
                 verdict=pkg.overall_verdict.value,
                 risk=pkg.risk.score if pkg.risk else None,
                 trace_steps=len(pkg.agent_trace), tool_calls=tool_calls,
                 duration_seconds=round(duration, 3))
        return pkg

    async def _collect_batch(self, state: InvestigationState,
                             trace: list[AgentTraceStep], started: float,
                             ) -> tuple[int, int]:
        """Flat re-plan loop (default strategy)."""
        step_no = 0
        tool_calls = 0
        for iteration in range(1, self.budget.max_iterations + 1):
            if time.monotonic() - started > self.budget.max_wall_clock_seconds:
                step_no += 1
                trace.append(AgentTraceStep(
                    step=step_no, iteration=iteration, phase="plan",
                    action="stop", ok=False,
                    reason="wall-clock budget exhausted",
                    outcome="finalizing on partial evidence"))
                break
            actions = self.planner.next_actions(state)
            if not actions:
                break
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
                *(self.run_tool(state, a) for a in actions))
            tool_calls += len(actions)
            for action, (ok, outcome, duration_ms, started_at) in zip(
                    actions, results, strict=True):
                step_no += 1
                trace.append(AgentTraceStep(
                    step=step_no, iteration=iteration, phase="act",
                    action=action.tool, reason=action.reason, outcome=outcome,
                    ok=ok, duration_ms=duration_ms, started_at=started_at))
        return step_no, tool_calls

    async def _collect_taskgraph(self, state: InvestigationState,
                                 pkg: InvestigationPackage,
                                 trace: list[AgentTraceStep]) -> tuple[int, int]:
        """Dependency-aware Task Graph + Priority Scheduler strategy. Produces the
        same trace as the batch loop plus a visualizable plan graph on the package.
        """
        from app.agents.planning import PriorityScheduler
        from app.agents.reflection import build_reflection_engine

        async def execute(state_, tool, params):
            return await self.run_tool(state_, PlannedAction(tool=tool, reason="",
                                                             params=params))

        scheduler = PriorityScheduler(
            execute, budget=self.budget,
            reflect=build_reflection_engine().suggest)
        result = await scheduler.run(state)
        pkg.plan_graph = result.graph.to_plan_nodes()

        step_no = 0
        tool_calls = 0
        for task in sorted(result.graph.all(), key=lambda t: (t.wave, t.id)):
            if task.attempts == 0:
                continue
            step_no += 1
            tool_calls += task.attempts
            trace.append(AgentTraceStep(
                step=step_no, iteration=task.wave, phase="act",
                action=task.tool, reason=task.reason, outcome=task.outcome,
                ok=task.ok, duration_ms=task.duration_ms))
        return step_no, tool_calls

    async def run_tool(
        self, state: InvestigationState, action: PlannedAction,
    ) -> tuple[bool, str, float, datetime]:
        started_at = datetime.now(UTC)
        t0 = time.monotonic()
        try:
            with span("agent.tool", tool=action.tool):
                spec = self.toolbox.registry.get(action.tool)
                outcome = await spec.fn(state, **action.params)
            registry().inc("aegis_tool_calls_total", tool=action.tool, ok="true")
            return True, outcome, (time.monotonic() - t0) * 1000, started_at
        except Exception as exc:  # noqa: BLE001 - single tool failure must not kill the case
            log.warning("tool_failed", tool=action.tool, error=str(exc))
            state.errors.append(f"{action.tool}: {exc}")
            registry().inc("aegis_tool_calls_total", tool=action.tool, ok="false")
            return False, f"error: {exc}", (time.monotonic() - t0) * 1000, started_at

    async def finalize(self, pkg: InvestigationPackage, state: InvestigationState,
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

        pkg.detections = state.detections
        has_mal_url = any(
            e.ioc.type.value == "url" and e.verdict is Verdict.MALICIOUS
            for e in pkg.iocs)
        pkg.mitre = map_techniques(state.signals, has_malicious_url=has_mal_url)
        # Detection rules carry their own ATT&CK mapping; union it in (dedup by id).
        known = {t.technique_id for t in pkg.mitre}
        for match in state.detections:
            for tech in match.techniques:
                if tech.technique_id not in known:
                    pkg.mitre.append(tech)
                    known.add(tech.technique_id)
        note("map_mitre", "Tag observed behaviors with ATT&CK techniques "
             "(keyword mapper + detection-rule mappings)",
             f"{len(pkg.mitre)} techniques, {len(state.detections)} detections")

        pkg.risk = score_investigation(RiskInputs(
            enriched_iocs=pkg.iocs,
            sandbox_malscore=state.sandbox_malscore,
            edr_confirmed_hits=len(state.edr_hits),
            mitre=pkg.mitre,
            asset_criticality=_asset_criticality(pkg.affected_hosts),
            recipient_count=len(pkg.affected_users),
        ))
        note("score_risk", "Fuse TI/sandbox/EDR/ATT&CK/asset factors into 0-100 risk",
             f"risk={pkg.risk.score:.0f}")

        # Consensus: the final verdict is a weighted vote of independent evidence
        # sources, never a single agent's call — with explainable confidence,
        # alternative hypotheses, and supporting/rejected observations.
        from app.agents.consensus import build_consensus_engine

        pkg.consensus = build_consensus_engine().decide(
            iocs=pkg.iocs, edr_hit_count=len(state.edr_hits),
            sandbox_malscore=state.sandbox_malscore, detections=pkg.detections,
            mitre=pkg.mitre)
        pkg.overall_verdict = pkg.consensus.verdict
        note("consensus", "Aggregate independent evidence sources into an "
             "explainable verdict (no single agent decides)",
             f"verdict={pkg.overall_verdict.value} "
             f"confidence={pkg.consensus.confidence:.0%} "
             f"({len(pkg.consensus.votes)} voters)")

        # Incident DNA: compute typed fingerprints, compare against prior
        # incidents (before storing this one), then persist for future compares.
        from app.engines.fingerprint import (
            build_fingerprint_engine,
            build_fingerprint_store,
        )

        fp_engine = build_fingerprint_engine()
        fp_store = build_fingerprint_store()
        pkg.incident_dna = fp_engine.compute(pkg)
        priors = fp_store.all_for_tenant(pkg.tenant)
        pkg.dna_matches = fp_engine.match(pkg.incident_dna, priors)
        fp_store.store(pkg.tenant, pkg.incident_dna, pkg.alert.title)
        note("incident_dna", "Fingerprint the incident (infra/malware/TTP/identity) "
             "and compare against prior incidents",
             f"{len(pkg.dna_matches)} fingerprint match(es)")

        # Threat-actor-type attribution from this incident's own TTP/infra/malware
        # profile (never a fabricated named group; unattributed when weak).
        from app.engines.campaign import build_attribution_engine

        infra_fp = pkg.incident_dna.by_kind("infrastructure")
        malware_fp = pkg.incident_dna.by_kind("malware")
        pkg.attribution = build_attribution_engine().attribute(
            techniques={t.technique_id for t in pkg.mitre},
            tactics={t.tactic for t in pkg.mitre},
            infra_count=len(infra_fp.features) if infra_fp else 0,
            malware_count=len(malware_fp.features) if malware_fp else 0,
            identity_count=len(pkg.affected_users),
            host_count=len(pkg.affected_hosts))
        note("attribution", "Estimate threat-actor type from the TTP/infra/malware "
             "profile (type only, never a named group)",
             f"{pkg.attribution.actor_type} "
             f"({pkg.attribution.confidence:.0%})")

        # Self-review: record residual gaps/unverified conclusions/contradictions
        # after all collection (and any reflection-driven follow-ups) — every
        # investigation self-reviews, regardless of strategy.
        from app.agents.reflection import build_reflection_engine

        pkg.reflections = build_reflection_engine().review(state)
        note("self_review", "Reflect on residual gaps, unverified conclusions and "
             "contradictions in the collected evidence",
             f"{len(pkg.reflections)} residual finding(s)")

        # Root cause (kill-chain origin) and business impact — deterministic,
        # grounded in the case's own timeline/graph/blast-radius.
        from app.agents.specialists import get_agent_bundle

        bundle = get_agent_bundle()
        pkg.root_cause = bundle.root_cause.analyze(pkg.timeline, pkg.mitre)
        pkg.business_impact = bundle.business_impact.analyze(
            affected_hosts=pkg.affected_hosts,
            affected_users=pkg.affected_users,
            verdict=pkg.overall_verdict,
            risk_score=pkg.risk.score,
        )
        note("assess_impact",
             "Reconstruct root cause + estimate business impact",
             f"origin={pkg.root_cause.initial_vector}; "
             f"impact={pkg.business_impact.level.value}")

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
            requests = self.approvals.create_for_package(pkg)
            pkg.approval_ids = [r.approval_id for r in requests]
            if requests:
                note("request_approvals",
                     "Containment actions require human approval (never "
                     "auto-executed)",
                     f"{len(requests)} approval request(s) pending")
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
        try:
            self.case_index.index_package(pkg)
        except Exception as exc:  # noqa: BLE001 - indexing must never fail a case
            log.warning("case_indexing_failed", error=str(exc))

    def _write_graph(self, pkg: InvestigationPackage) -> None:
        alert_node = f"alert:{pkg.alert.source_alert_id}"
        triples = [GraphTriple(alert_node, "contains", e.ioc.key()) for e in pkg.iocs]
        triples += [GraphTriple(f"host:{h}", "affected_by", alert_node)
                    for h in pkg.affected_hosts]
        triples += [GraphTriple(f"user:{u}", "received", alert_node)
                    for u in pkg.affected_users]
        if triples:
            self.graph.upsert(pkg.tenant, triples)


def _asset_criticality(hosts: list[str]) -> float:
    # Hosts in the finance segment are treated as high-criticality (demo heuristic;
    # production reads from a CMDB/asset inventory).
    if any("FIN" in h.upper() for h in hosts):
        return 0.9
    return 0.5 if hosts else 0.3
