"""Consensus + confidence engine: multi-voter fusion, explainability, parity."""
from __future__ import annotations

import pytest

from app.agents.consensus import ConsensusEngine
from app.schemas.common import IOCType, Severity, Verdict
from app.schemas.investigation import DetectionMatch, MitreTechnique
from app.schemas.ioc import IOC, EnrichedIOC, SourceVerdict


def mal_ioc(value: str, score: float = 0.97) -> EnrichedIOC:
    return EnrichedIOC(
        ioc=IOC(type=IOCType.DOMAIN, value=value), verdict=Verdict.MALICIOUS,
        confidence=0.65,
        sources=[SourceVerdict(source="ti", verdict=Verdict.MALICIOUS, score=score)])


def det(sev: Severity) -> DetectionMatch:
    return DetectionMatch(rule_id="R-1", title="t", severity=sev)


# ---------------------------------------------------------------- fusion


def test_no_evidence_is_unknown():
    r = ConsensusEngine().decide(iocs=[], edr_hit_count=0, sandbox_malscore=0.0,
                                 detections=[], mitre=[])
    assert r.verdict is Verdict.UNKNOWN and r.confidence == 0.0


def test_multiple_strong_sources_reach_malicious_with_high_confidence():
    r = ConsensusEngine().decide(
        iocs=[mal_ioc("evil.com")], edr_hit_count=2, sandbox_malscore=0.92,
        detections=[det(Severity.HIGH)],
        mitre=[MitreTechnique(technique_id="T1071", name="C2",
                              tactic="command-and-control")])
    assert r.verdict is Verdict.MALICIOUS
    assert r.confidence > 0.7
    assert {v.voter for v in r.votes} == {"threat_intel", "edr", "sandbox",
                                          "detections", "mitre"}


def test_single_weak_voter_is_low_confidence():
    """One source only -> confidence is penalized (no single agent decides)."""
    r = ConsensusEngine().decide(
        iocs=[], edr_hit_count=0, sandbox_malscore=0.0,
        detections=[det(Severity.MEDIUM)], mitre=[])
    assert len(r.votes) == 1
    assert r.confidence < 0.5
    assert any("single" in x.lower() or "one" in x.lower() for x in r.rejected)


def test_ti_and_sandbox_without_edr_still_malicious():
    """TI + sandbox agreeing is not an unsupported conclusion — EDR absence must
    not, by itself, drop a well-corroborated malicious verdict."""
    r = ConsensusEngine().decide(
        iocs=[mal_ioc("evil.com")], edr_hit_count=0, sandbox_malscore=0.92,
        detections=[det(Severity.MEDIUM)],
        mitre=[MitreTechnique(technique_id="T1566", name="Phishing",
                              tactic="initial-access")])
    assert r.verdict is Verdict.MALICIOUS


def test_benign_when_sources_are_clean():
    clean = EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="good.com"),
                        verdict=Verdict.BENIGN, confidence=0.6,
                        sources=[SourceVerdict(source="ti", verdict=Verdict.BENIGN,
                                               score=0.05)])
    r = ConsensusEngine().decide(iocs=[clean], edr_hit_count=0,
                                 sandbox_malscore=0.0, detections=[], mitre=[])
    assert r.verdict is Verdict.BENIGN


# ---------------------------------------------------------------- explainability


def test_result_is_fully_explainable():
    r = ConsensusEngine().decide(
        iocs=[mal_ioc("evil.com")], edr_hit_count=1, sandbox_malscore=0.9,
        detections=[det(Severity.CRITICAL)], mitre=[])
    # Every explainability facet is populated.
    assert r.votes and r.hypotheses and r.supporting and r.reasoning
    # The chosen verdict appears among the ranked hypotheses.
    assert any(h.verdict is r.verdict for h in r.hypotheses)
    # Reasoning chain names the sources and ends with the fused decision.
    assert any("Weighted malice" in step for step in r.reasoning)
    # Hypothesis probabilities are a distribution (sum ~ 1 over vote buckets).
    assert abs(sum(h.probability for h in r.hypotheses) - 1.0) < 0.01


def test_disagreement_lowers_agreement_and_records_rejected():
    # sandbox says malicious, but a benign-heavy TI + clean detections pull back.
    r = ConsensusEngine().decide(
        iocs=[EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="x.com"),
                          verdict=Verdict.BENIGN, confidence=0.6,
                          sources=[SourceVerdict(source="ti", verdict=Verdict.BENIGN,
                                                 score=0.05)])],
        edr_hit_count=0, sandbox_malscore=0.92, detections=[], mitre=[])
    assert r.agreement < 1.0
    assert r.rejected  # the dissenting voter is recorded


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_investigation_attaches_consensus():
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("acme", make_phishing_alert())
    assert pkg.consensus is not None
    assert pkg.overall_verdict is pkg.consensus.verdict  # consensus is authoritative
    assert pkg.consensus.confidence > 0
    assert len(pkg.consensus.votes) >= 3  # multiple independent sources voted
    assert any(s.action == "consensus" for s in pkg.agent_trace)
