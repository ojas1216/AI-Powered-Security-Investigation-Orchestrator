"""Specialist-agent framework: registry, typed agents, and the /agents API."""
from __future__ import annotations

import pytest

from app.agents.specialists import (
    AgentRegistry,
    IocExtractionAgent,
    MitreAgent,
    ThreatIntelAgent,
    build_agent_bundle,
)
from app.agents.specialists.base import AgentResult, SpecialistAgent
from app.engines.threat_intel import build_aggregator

# ---------------------------------------------------------------- registry


def test_registry_rejects_duplicates_and_non_async():
    reg = AgentRegistry()
    reg.register(IocExtractionAgent())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(IocExtractionAgent())

    class BadAgent(SpecialistAgent):
        name = "bad"

        def run(self, payload, *, tenant):  # not async
            return None

    with pytest.raises(TypeError, match="must be async"):
        reg.register(BadAgent())


def test_bundle_exposes_all_capabilities():
    catalog = {a.name for a in build_agent_bundle().orchestrator().catalog()}
    assert catalog == {
        # engine-wrapping agents
        "ioc_extraction", "threat_intel", "detection", "edr_hunt", "sandbox",
        "email", "mitre", "risk", "memory",
        # generation & higher-order analytic agents
        "sigma_generator", "yara_generator", "root_cause", "attack_path",
        "business_impact",
    }


# ---------------------------------------------------------------- agents


@pytest.mark.asyncio
async def test_ioc_extraction_agent_defang_aware():
    r = await IocExtractionAgent().run({"text": "beacon to hxxps://evil[.]com/pay"},
                                       tenant="acme")
    assert isinstance(r, AgentResult) and r.ok
    values = {i["value"] for i in r.data["iocs"]}
    assert "evil.com" in values


@pytest.mark.asyncio
async def test_threat_intel_agent_independently_callable():
    agent = ThreatIntelAgent(build_aggregator())
    r = await agent.run({"indicators": ["malware-c2.net", "8.8.8.8"]}, tenant="acme")
    verdicts = {i["ioc"]["value"]: i["verdict"] for i in r.data["iocs"]}
    assert verdicts["malware-c2.net"] == "malicious"


@pytest.mark.asyncio
async def test_threat_intel_agent_reports_no_indicators():
    agent = ThreatIntelAgent(build_aggregator())
    r = await agent.run({"text": "no indicators in this sentence"}, tenant="acme")
    assert r.ok is False


@pytest.mark.asyncio
async def test_mitre_agent_maps_from_signals():
    r = await MitreAgent().run(
        {"signals": ["powershell -enc"], "has_malicious_url": True}, tenant="acme")
    ids = {t["technique_id"] for t in r.data["techniques"]}
    assert "T1059.001" in ids and "T1566.002" in ids


@pytest.mark.asyncio
async def test_loop_delegates_to_specialists_no_behavior_change():
    """The autonomous loop must produce the same verdict now that its tools
    delegate the analytic work to specialist agents."""
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("acme", make_phishing_alert())
    assert pkg.overall_verdict.value == "malicious"
    assert "malware-c2.net" in {e.ioc.value for e in pkg.iocs}


# ---------------------------------------------------------------- API


def hunter(tenant: str = "acme") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "threat_hunter",
            "Authorization": "Bearer dev"}


def test_list_agents_requires_permission(client):
    assert client.get("/api/v1/agents").status_code == 401
    tier1 = {"X-Tenant-ID": "acme", "X-Roles": "tier1_analyst",
             "Authorization": "Bearer dev"}
    assert client.get("/api/v1/agents", headers=tier1).status_code == 403


def test_list_agents_catalog(client):
    resp = client.get("/api/v1/agents", headers=hunter())
    assert resp.status_code == 200
    names = {a["name"] for a in resp.json()}
    assert {"threat_intel", "edr_hunt", "mitre"} <= names
    # discovery metadata present
    ti = next(a for a in resp.json() if a["name"] == "threat_intel")
    assert ti["description"] and ti["input_hint"]


def test_run_agent_end_to_end(client):
    resp = client.post("/api/v1/agents/threat_intel/run", headers=hunter(),
                       json={"payload": {"indicators": ["evil.com"]}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent"] == "threat_intel"
    assert body["data"]["iocs"][0]["verdict"] == "malicious"


def test_run_unknown_agent_404(client):
    resp = client.post("/api/v1/agents/nope/run", headers=hunter(),
                       json={"payload": {}})
    assert resp.status_code == 404


def test_run_detection_agent_via_api(client):
    resp = client.post("/api/v1/agents/detection/run", headers=hunter(),
                       json={"payload": {"raw_text": "powershell -enc aQB3AHIA"}})
    assert resp.status_code == 200
    fired = {d["rule_id"] for d in resp.json()["data"]["detections"]}
    assert "AEG-1001" in fired
