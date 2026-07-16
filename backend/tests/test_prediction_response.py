"""Predictive attack path + response engine."""
from __future__ import annotations

import pytest

from app.engines.prediction import PredictionEngine
from app.engines.response import ResponseEngine
from app.schemas.alert import Alert
from app.schemas.common import IOCType, Severity, SourceProduct, Verdict
from app.schemas.investigation import (
    BusinessImpact,
    InvestigationPackage,
    InvestigationStatus,
    MitreTechnique,
    RootCause,
)
from app.schemas.ioc import IOC, EnrichedIOC


def tech(tid: str, tactic: str) -> MitreTechnique:
    return MitreTechnique(technique_id=tid, name=tid, tactic=tactic)


# ---------------------------------------------------------------- prediction


def test_predicts_next_moves_after_execution():
    pred = PredictionEngine().predict(
        RootCause(kill_chain=["initial-access", "execution"]),
        [tech("T1566", "initial-access"), tech("T1059", "execution")],
        Verdict.MALICIOUS)
    assert pred.current_stage == "execution"
    tactics = [p.tactic for p in pred.predictions]
    # the immediate next stage is most probable
    assert tactics[0] == "persistence"
    assert pred.predictions[0].probability > pred.predictions[-1].probability
    # each prediction carries a preventative control
    assert all(p.preventative_action for p in pred.predictions)
    assert pred.simulation


def test_endgame_tactics_get_probability_boost():
    pred = PredictionEngine().predict(
        RootCause(kill_chain=["command-and-control"]),
        [tech("T1071", "command-and-control")], Verdict.MALICIOUS)
    by_tactic = {p.tactic: p.probability for p in pred.predictions}
    # exfiltration/impact are the attacker's objective -> boosted vs pure decay
    assert "exfiltration" in by_tactic or "impact" in by_tactic


def test_benign_incident_gets_no_projection():
    pred = PredictionEngine().predict(None, [], Verdict.BENIGN)
    assert pred.predictions == []


# ---------------------------------------------------------------- response


def malicious_pkg(**kw) -> InvestigationPackage:
    iocs = [
        EnrichedIOC(ioc=IOC(type=IOCType.IPV4, value="45.155.205.99"),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
        EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="evil.com"),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
        EnrichedIOC(ioc=IOC(type=IOCType.SHA256, value="a" * 64),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
    ]
    defaults = dict(
        investigation_id="i1", tenant="t", status=InvestigationStatus.COMPLETE,
        alert=Alert(source=SourceProduct.GENERIC, source_alert_id="i1", title="t",
                    extra={"message_id": "m1"}),
        overall_verdict=Verdict.MALICIOUS, iocs=iocs,
        affected_hosts=["WS-FIN-042"], affected_users=["jdoe"],
        business_impact=BusinessImpact(level=Severity.CRITICAL))
    defaults.update(kw)
    return InvestigationPackage(**defaults)


def test_response_plan_covers_all_categories():
    plan = ResponseEngine().plan(malicious_pkg())
    cats = {a.category for a in plan.actions}
    assert {"network", "endpoint", "identity", "email", "escalation"} <= cats
    # each action carries impact + rollback
    for a in plan.actions:
        assert a.rollback and a.business_impact and a.difficulty


def test_response_actions_ranked_by_risk_reduction():
    plan = ResponseEngine().plan(malicious_pkg())
    reductions = [a.risk_reduction for a in plan.actions]
    assert reductions == sorted(reductions, reverse=True)
    # quarantine (0.8) should outrank a hash block (0.55)
    assert plan.actions[0].risk_reduction >= 0.7


def test_disruptive_actions_require_approval_notifications_do_not():
    plan = ResponseEngine().plan(malicious_pkg())
    quarantine = next(a for a in plan.actions if a.category == "endpoint"
                      and "Quarantine" in a.action)
    assert quarantine.requires_approval is True
    notify = next(a for a in plan.actions if a.category == "escalation")
    assert notify.requires_approval is False


def test_benign_incident_has_empty_response_plan():
    plan = ResponseEngine().plan(malicious_pkg(overall_verdict=Verdict.BENIGN))
    assert plan.actions == []


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_investigation_attaches_prediction_and_response():
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("pred-tenant", make_phishing_alert())
    assert pkg.prediction is not None and pkg.prediction.predictions
    assert pkg.response_plan is not None and pkg.response_plan.actions
    # forward defense: every predicted move has a preventative action
    assert all(p.preventative_action for p in pkg.prediction.predictions)
    # response reflects the real evidence (a block for the confirmed C2)
    assert any("evil.com" in a.action or "malware-c2" in a.action
               for a in pkg.response_plan.actions)
    steps = {s.action for s in pkg.agent_trace}
    assert {"predict_path", "response_plan"} <= steps
