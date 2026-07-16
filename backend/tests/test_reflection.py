"""Reflection loop: self-review findings, follow-up suggestions, scheduler rounds."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agents.reflection import ReflectionEngine
from app.agents.state import InvestigationState
from app.engines.edr.base import EDRHit
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, EnrichedIOC, SourceVerdict
from tests.test_agents import make_investigator, make_phishing_alert


def enriched(value: str, type_: IOCType, verdict: Verdict,
             sources: list[SourceVerdict]) -> EnrichedIOC:
    return EnrichedIOC(ioc=IOC(type=type_, value=value), verdict=verdict,
                       confidence=0.9, sources=sources)


def src(name: str, verdict: Verdict) -> SourceVerdict:
    return SourceVerdict(source=name, verdict=verdict, score=0.9)


def state_with(**enriched_map) -> InvestigationState:
    st = InvestigationState(tenant="t", alert=make_phishing_alert())
    for e in enriched_map.values():
        st.enriched[e.ioc.key()] = e
    return st


# ---------------------------------------------------------------- analysis


def test_flags_unhunted_suspicious_ioc():
    e = enriched("odd.example", IOCType.DOMAIN, Verdict.SUSPICIOUS,
                 [src("mock-ti", Verdict.SUSPICIOUS)])
    st = state_with(a=e)  # not in hunted_keys
    findings = ReflectionEngine().review(st)
    assert any(f.category == "gap" and "suspicious" in f.detail for f in findings)
    actions = ReflectionEngine().suggest(st)
    assert any(a.tool == "hunt_edr" for a in actions)


def test_flags_single_source_malicious_without_confirmation():
    e = enriched("lonely.example", IOCType.DOMAIN, Verdict.MALICIOUS,
                 [src("mock-ti", Verdict.MALICIOUS)])
    st = state_with(a=e)
    findings = ReflectionEngine().review(st)
    assert any(f.category == "unverified" for f in findings)
    # proposes an independent EDR hunt to verify
    assert any(a.tool == "hunt_edr" for a in ReflectionEngine().suggest(st))


def test_single_source_malicious_confirmed_by_edr_is_not_flagged():
    e = enriched("confirmed.example", IOCType.DOMAIN, Verdict.MALICIOUS,
                 [src("mock-ti", Verdict.MALICIOUS)])
    st = state_with(a=e)
    st.edr_hits.append(EDRHit(ioc=e.ioc, host="WS-1",
                              observed_at=datetime.now(UTC)))
    findings = ReflectionEngine().review(st)
    assert not any(f.category == "unverified" for f in findings)


def test_flags_source_contradiction():
    e = enriched("mixed.example", IOCType.DOMAIN, Verdict.SUSPICIOUS,
                 [src("feed-a", Verdict.MALICIOUS), src("feed-b", Verdict.BENIGN)])
    st = state_with(a=e)
    findings = ReflectionEngine().review(st)
    assert any(f.category == "contradiction" for f in findings)


def test_flags_coverage_gap_for_pending_iocs():
    st = InvestigationState(tenant="t", alert=make_phishing_alert())
    st.pending_iocs["domain:x.example"] = IOC(type=IOCType.DOMAIN, value="x.example")
    actions = ReflectionEngine().suggest(st)
    assert any(a.tool == "enrich_iocs" for a in actions)


def test_suggest_is_deduplicated():
    e1 = enriched("s1.example", IOCType.DOMAIN, Verdict.SUSPICIOUS,
                  [src("ti", Verdict.SUSPICIOUS)])
    e2 = enriched("s2.example", IOCType.DOMAIN, Verdict.SUSPICIOUS,
                  [src("ti", Verdict.SUSPICIOUS)])
    st = state_with(a=e1, b=e2)
    # both suspicious -> a single hunt_edr action carrying both keys
    actions = ReflectionEngine().suggest(st)
    hunts = [a for a in actions if a.tool == "hunt_edr"]
    assert len(hunts) == 1


def test_clean_investigation_has_no_actionable_findings():
    e = enriched("evil.example", IOCType.DOMAIN, Verdict.MALICIOUS,
                 [src("a", Verdict.MALICIOUS), src("b", Verdict.MALICIOUS)])
    st = state_with(a=e)
    st.edr_hits.append(EDRHit(ioc=e.ioc, host="WS-1",
                              observed_at=datetime.now(UTC)))
    st.hunted_keys.add(e.ioc.key())
    assert ReflectionEngine().suggest(st) == []


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_investigation_records_reflection_findings_both_strategies():
    for strategy in ("batch", "taskgraph"):
        agent = make_investigator()
        agent.strategy = strategy
        pkg = await agent.investigate("acme", make_phishing_alert())
        # every investigation self-reviews; the field is always populated-or-empty
        assert isinstance(pkg.reflections, list)
        assert pkg.overall_verdict.value == "malicious"
        assert any(s.action == "self_review" for s in pkg.agent_trace)


@pytest.mark.asyncio
async def test_reflection_loop_converges_and_hunts_suspicious():
    """The taskgraph strategy must run reflection: if suspicious IOCs exist and
    were never hunted, reflection re-opens a hunt task. The loop then stabilizes
    (no residual gap/coverage findings that are actionable)."""
    agent = make_investigator()
    agent.strategy = "taskgraph"
    pkg = await agent.investigate("acme", make_phishing_alert())

    # After reflection, no *actionable* coverage/gap findings should remain:
    # everything hunt-able was hunted (residual findings, if any, are the
    # non-actionable "single feed, no on-host activity" kind or contradictions).
    residual_actionable = [
        f for f in pkg.reflections
        if f.category in ("coverage", "gap") and f.action_recommended
    ]
    assert residual_actionable == []
