"""Unit tests for the risk scoring engine."""
from __future__ import annotations

from app.engines.risk_scoring import score_investigation
from app.engines.risk_scoring.scorer import RiskInputs
from app.schemas.common import IOCType, Severity, Verdict
from app.schemas.investigation import MitreTechnique
from app.schemas.ioc import IOC, EnrichedIOC


def _mal_ioc(conf=0.95):
    return EnrichedIOC(
        ioc=IOC(type=IOCType.DOMAIN, value="evil.com"),
        verdict=Verdict.MALICIOUS, confidence=conf,
    )


def test_benign_scores_low():
    r = score_investigation(RiskInputs())
    assert r.severity in (Severity.LOW, Severity.MEDIUM)
    assert r.score < 30


def test_full_kill_chain_scores_critical():
    r = score_investigation(RiskInputs(
        enriched_iocs=[_mal_ioc()],
        sandbox_malscore=0.92,
        edr_confirmed_hits=3,
        mitre=[
            MitreTechnique(technique_id="T1071.001", name="C2", tactic="command-and-control"),
            MitreTechnique(technique_id="T1547.001", name="Run key", tactic="persistence"),
        ],
        asset_criticality=0.9,
        recipient_count=40,
    ))
    assert r.severity == Severity.CRITICAL
    assert r.score >= 80
    assert r.rationale  # explainable


def test_factors_present_and_weighted():
    r = score_investigation(RiskInputs(enriched_iocs=[_mal_ioc()], edr_confirmed_hits=1))
    assert "threat_intel" in r.factors
    assert "edr_evidence" in r.factors
    assert 0 <= r.score <= 100


def test_edr_evidence_raises_score():
    base = score_investigation(RiskInputs(enriched_iocs=[_mal_ioc()])).score
    with_edr = score_investigation(
        RiskInputs(enriched_iocs=[_mal_ioc()], edr_confirmed_hits=3)
    ).score
    assert with_edr > base
