"""Tests for the agentic core: planner, autonomous loop, memory, resilience."""
from __future__ import annotations

import pytest

from app.agents import AutonomousInvestigator, Budget, InMemoryCaseMemory, Planner
from app.agents.memory import CaseRecord, similarity
from app.agents.state import InvestigationState
from app.agents.tools import Toolbox
from app.engines.copilot import build_copilot
from app.engines.edr import build_edr
from app.engines.edr.base import EDRConnector
from app.engines.email_investigation import build_email
from app.engines.evidence import build_evidence_store
from app.engines.graph import build_graph
from app.engines.sandbox import build_sandbox
from app.engines.threat_intel import build_aggregator
from app.engines.ticketing import build_ticketing
from app.schemas.alert import Alert
from app.schemas.common import (
    InvestigationStatus,
    SourceProduct,
    Verdict,
)
from app.schemas.ioc import IOC, EnrichedIOC


def make_phishing_alert(**overrides) -> Alert:
    defaults = dict(
        source=SourceProduct.SENTINEL,
        source_alert_id="INC-1",
        title="Phishing email reported by user",
        description="Body has hxxps://evil[.]com/pay and Invoice_8841.lnk on WS-FIN-042",
        raw_text="",
        users=["jdoe"],
        hosts=["WS-FIN-042"],
        extra={"message_id": "phish-0001"},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def make_investigator(*, budget: Budget | None = None,
                      memory: InMemoryCaseMemory | None = None,
                      edr: EDRConnector | None = None) -> AutonomousInvestigator:
    toolbox = Toolbox(
        ti=build_aggregator(),
        sandbox=build_sandbox(),
        edr=edr or build_edr(),
        email=build_email(),
        evidence=build_evidence_store(),
        copilot=build_copilot(),
        ticketing=build_ticketing(),
    )
    return AutonomousInvestigator(
        toolbox=toolbox, graph=build_graph(),
        memory=memory or InMemoryCaseMemory(), budget=budget,
    )


# ---------------------------------------------------------------- planner


def test_planner_fetches_email_and_detections_before_extraction():
    state = InvestigationState(tenant="t", alert=make_phishing_alert())
    planner = Planner()

    first = planner.next_actions(state)
    # Detections and email context are independent -> same concurrent batch.
    assert {a.tool for a in first} == {"run_detections", "fetch_email_context"}
    assert all(a.reason for a in first)  # every action is explained

    state.detections_ran = True
    state.email_checked = True
    second = planner.next_actions(state)
    assert [a.tool for a in second] == ["extract_iocs"]


@pytest.mark.asyncio
async def test_planner_batches_enrichment_and_detonation_concurrently():
    """Once extraction ran, TI enrichment and sandbox detonation are independent
    and must be planned in the same batch; the hunt must wait for both."""
    state = InvestigationState(tenant="t", alert=make_phishing_alert())
    state.email_msg = await build_email().get_message("phish-0001")
    state.detections_ran = True
    state.email_checked = True
    state.extracted = True
    state.add_iocs([IOC(type="domain", value="evil.com")])

    actions = Planner().next_actions(state)
    tools = [a.tool for a in actions]
    assert "enrich_iocs" in tools
    assert "detonate_attachment" in tools
    assert "hunt_edr" not in tools  # its target set is still changing


def test_planner_hunts_everything_once_when_ti_is_silent():
    state = InvestigationState(tenant="t", alert=make_phishing_alert(
        title="Odd beacon", description="no phish here", extra={}))
    state.detections_ran = True
    state.email_checked = True
    state.extracted = True
    ioc = IOC(type="domain", value="unknown-widget.example")
    state.enriched[ioc.key()] = EnrichedIOC(ioc=ioc, verdict=Verdict.UNKNOWN)

    actions = Planner().next_actions(state)
    assert [a.tool for a in actions] == ["hunt_edr"]
    assert actions[0].params["ioc_keys"] == [ioc.key()]

    state.hunted_keys.add(ioc.key())
    assert Planner().next_actions(state) == []  # converged


# ---------------------------------------------------------------- loop


@pytest.mark.asyncio
async def test_autonomous_loop_follows_dropped_iocs():
    """The differentiating behavior: sandbox-dropped IOCs must trigger a second
    enrichment pass and be hunted — the loop re-plans on new evidence."""
    agent = make_investigator()
    pkg = await agent.investigate("acme", make_phishing_alert())

    assert pkg.status == InvestigationStatus.COMPLETE
    assert pkg.overall_verdict == Verdict.MALICIOUS

    ioc_values = {e.ioc.value for e in pkg.iocs}
    assert "malware-c2.net" in ioc_values, "dropped IOC was not folded back in"
    assert pkg.affected_hosts == ["WS-FIN-042"]

    acts = [s for s in pkg.agent_trace if s.phase == "act"]
    enrich_passes = [s for s in acts if s.action == "enrich_iocs"]
    assert len(enrich_passes) >= 2, "sandbox drop should force a re-enrichment pass"
    assert any(s.action == "hunt_edr" for s in acts)
    assert all(s.reason for s in pkg.agent_trace), "every step must be explained"
    assert [s.step for s in pkg.agent_trace] == list(
        range(1, len(pkg.agent_trace) + 1))


@pytest.mark.asyncio
async def test_tool_failure_degrades_gracefully():
    class BrokenEDR(EDRConnector):
        name = "broken-edr"

        async def hunt(self, iocs):
            raise ConnectionError("EDR API 503")

    agent = make_investigator(edr=BrokenEDR())
    pkg = await agent.investigate("acme", make_phishing_alert())

    assert pkg.status == InvestigationStatus.COMPLETE
    failed = [s for s in pkg.agent_trace if s.action == "hunt_edr" and not s.ok]
    assert failed and "503" in failed[0].outcome
    # TI still confirmed malicious IOCs, so the verdict holds without EDR
    assert pkg.overall_verdict == Verdict.MALICIOUS
    assert pkg.affected_hosts == []


@pytest.mark.asyncio
async def test_tool_call_budget_stops_collection_but_still_finalizes():
    agent = make_investigator(budget=Budget(max_tool_calls=2))
    pkg = await agent.investigate("acme", make_phishing_alert())

    assert pkg.status == InvestigationStatus.COMPLETE
    stops = [s for s in pkg.agent_trace if s.action == "stop"]
    assert stops and "budget" in stops[0].reason
    acts = [s for s in pkg.agent_trace if s.phase == "act"]
    assert len(acts) <= 2


# ---------------------------------------------------------------- memory


@pytest.mark.asyncio
async def test_memory_recalls_related_campaign_within_tenant():
    memory = InMemoryCaseMemory()
    agent = make_investigator(memory=memory)

    first = await agent.investigate("acme", make_phishing_alert())
    assert first.related_investigations == []  # nothing to recall yet

    second = await agent.investigate(
        "acme", make_phishing_alert(source_alert_id="INC-2"))
    assert second.related_investigations, "same campaign must be recalled"
    top = second.related_investigations[0]
    assert top.investigation_id == first.investigation_id
    assert top.shared_iocs, "recall must show the shared indicators"
    assert 0 < top.similarity <= 1


@pytest.mark.asyncio
async def test_memory_is_tenant_isolated():
    memory = InMemoryCaseMemory()
    agent = make_investigator(memory=memory)

    await agent.investigate("acme", make_phishing_alert())
    other = await agent.investigate("globex", make_phishing_alert(
        source_alert_id="INC-9"))
    assert other.related_investigations == [], "cross-tenant recall is forbidden"


def test_similarity_requires_shared_indicators():
    record = CaseRecord(
        investigation_id="i1", tenant="t", title="x", verdict=Verdict.MALICIOUS,
        risk_score=80.0, ioc_keys=frozenset({"domain:evil.com"}),
        technique_ids=frozenset({"T1566.002"}),
    )
    # technique overlap alone is not a campaign match
    assert similarity(record, frozenset({"domain:other.com"}),
                      frozenset({"T1566.002"})) is None
    match = similarity(record, frozenset({"domain:evil.com"}),
                       frozenset({"T1059.001"}))
    assert match is not None
    assert match.shared_iocs == ["domain:evil.com"]
