"""Generation & analytic agents: Sigma, YARA, root-cause, attack-path, impact."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agents.specialists import (
    AttackPathAgent,
    BusinessImpactAgent,
    RootCauseAgent,
    SigmaGeneratorAgent,
    YaraGeneratorAgent,
)
from app.engines.graph.client import GraphTriple, InMemoryGraph
from app.schemas.common import IOCType, Severity, Verdict
from app.schemas.investigation import DetectionMatch, MitreTechnique, TimelineEvent
from app.schemas.ioc import IOC, EnrichedIOC


def mal(type_: IOCType, value: str) -> EnrichedIOC:
    return EnrichedIOC(ioc=IOC(type=type_, value=value), verdict=Verdict.MALICIOUS,
                       confidence=0.9)


# ---------------------------------------------------------------- Sigma


def test_sigma_rule_is_grounded_in_iocs():
    sigma = SigmaGeneratorAgent().generate(
        title="Evil C2 beacon",
        iocs=[mal(IOCType.DOMAIN, "evil.com"), mal(IOCType.IPV4, "45.155.205.99")],
        detections=[DetectionMatch(
            rule_id="AEG-1001", title="x", severity=Severity.HIGH,
            techniques=[MitreTechnique(technique_id="T1071.001", name="C2",
                                       tactic="command-and-control")])],
    )
    assert "title: Evil C2 beacon" in sigma
    assert "evil.com" in sigma and "45.155.205.99" in sigma
    assert "condition:" in sigma
    assert "attack.t1071.001" in sigma  # technique tag lower-cased


def test_sigma_rule_without_iocs_still_valid():
    sigma = SigmaGeneratorAgent().generate(title="", iocs=[], detections=[])
    assert "detection:" in sigma and "condition:" in sigma


@pytest.mark.asyncio
async def test_sigma_agent_run():
    r = await SigmaGeneratorAgent().run(
        {"title": "t", "iocs": [mal(IOCType.DOMAIN, "bad.example").model_dump()]},
        tenant="acme")
    assert "bad.example" in r.data["sigma"]


# ---------------------------------------------------------------- YARA


def test_yara_rule_escapes_and_is_valid():
    yara = YaraGeneratorAgent().generate(
        rule_name="9bad-name!", hashes=["abc123"],
        filenames=['inv"oice.lnk'], strings=["MZ"])
    assert yara.startswith("rule r_9bad_name_")  # sanitized identifier
    assert '\\"' in yara  # quote escaped
    assert "condition:" in yara and "any of them" in yara
    assert 'hash0 = "abc123"' in yara


def test_yara_rule_with_no_strings_has_placeholder():
    yara = YaraGeneratorAgent().generate(rule_name="r", hashes=[], filenames=[],
                                         strings=[])
    assert "$a = " in yara


# ---------------------------------------------------------------- root cause


def test_root_cause_picks_earliest_kill_chain_tactic():
    tl = [
        TimelineEvent(timestamp=datetime(2026, 6, 8, 9, tzinfo=UTC),
                      action="IOC observed on host", source="edr"),
        TimelineEvent(timestamp=datetime(2026, 6, 8, 8, tzinfo=UTC),
                      action="Email delivered", source="email"),
    ]
    mitre = [
        MitreTechnique(technique_id="T1071.001", name="C2",
                       tactic="command-and-control"),
        MitreTechnique(technique_id="T1566.002", name="Spearphishing Link",
                       tactic="initial-access"),
    ]
    rc = RootCauseAgent().analyze(tl, mitre)
    assert rc.initial_vector == "Spearphishing Link (T1566.002)"  # earliest tactic
    assert rc.kill_chain[0] == "initial-access"
    assert rc.kill_chain[-1] == "command-and-control"
    assert rc.initial_event.action == "Email delivered"  # earliest timestamp


def test_root_cause_handles_empty():
    rc = RootCauseAgent().analyze([], [])
    assert rc.initial_vector == "undetermined"
    assert rc.initial_event is None


# ---------------------------------------------------------------- attack path


@pytest.mark.asyncio
async def test_attack_path_agent_uses_graph():
    g = InMemoryGraph()
    g.upsert("acme", [
        GraphTriple("host:WS-1", "affected_by", "alert:INC-1"),
        GraphTriple("alert:INC-1", "contains", "domain:evil.com"),
        GraphTriple("alert:INC-2", "contains", "domain:evil.com"),
        GraphTriple("host:WS-2", "affected_by", "alert:INC-2"),
    ])
    agent = AttackPathAgent(g)
    r = await agent.run({"src": "host:WS-1", "dst": "host:WS-2"}, tenant="acme")
    assert r.ok and "domain:evil.com" in r.summary

    missing = await agent.run({"src": "host:WS-1", "dst": "host:NOPE"}, tenant="acme")
    assert missing.ok is False


@pytest.mark.asyncio
async def test_attack_path_requires_both_endpoints():
    r = await AttackPathAgent(InMemoryGraph()).run({"src": "host:A"}, tenant="acme")
    assert r.ok is False


# ---------------------------------------------------------------- business impact


def test_business_impact_finance_host_is_critical():
    bi = BusinessImpactAgent().analyze(
        affected_hosts=["WS-FIN-042"], affected_users=["jdoe", "asmith"],
        verdict=Verdict.MALICIOUS, risk_score=75.0)
    assert bi.level is Severity.CRITICAL
    assert "finance" in bi.affected_asset_classes
    assert bi.blast_radius_hosts == 1 and bi.blast_radius_users == 2
    assert "$" in bi.estimated_cost_band


def test_business_impact_benign_is_low():
    bi = BusinessImpactAgent().analyze(
        affected_hosts=[], affected_users=[], verdict=Verdict.BENIGN, risk_score=5.0)
    assert bi.level is Severity.LOW


@pytest.mark.asyncio
async def test_impact_agent_run():
    r = await BusinessImpactAgent().run(
        {"affected_hosts": ["WS-FIN-1"], "verdict": "malicious", "risk_score": 90},
        tenant="acme")
    assert r.data["business_impact"]["level"] == "critical"


# ---------------------------------------------------------------- catalog + loop


def test_all_generation_agents_in_catalog():
    from app.agents.specialists import build_agent_bundle

    names = {a.name for a in build_agent_bundle().orchestrator().catalog()}
    assert {"sigma_generator", "yara_generator", "root_cause", "attack_path",
            "business_impact"} <= names


@pytest.mark.asyncio
async def test_investigation_package_carries_impact_and_root_cause():
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("acme", make_phishing_alert())
    assert pkg.business_impact is not None
    assert pkg.root_cause is not None
    assert pkg.business_impact.level in Severity
    assert pkg.root_cause.kill_chain  # phishing case has tactics
