"""Campaign detection (fingerprint clustering) + threat-actor-type attribution."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.engines.campaign import AttributionEngine, build_campaign_engine
from app.engines.fingerprint import build_fingerprint_engine
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, IOCType, SourceProduct, Verdict
from app.schemas.investigation import InvestigationPackage, MitreTechnique
from app.schemas.ioc import IOC, EnrichedIOC


def pkg(inv_id: str, *, domains=(), hashes=(), techniques=(), users=(), hosts=(),
        when=None, verdict=Verdict.MALICIOUS) -> InvestigationPackage:
    iocs = [EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value=d),
                        verdict=Verdict.MALICIOUS, confidence=0.9) for d in domains]
    iocs += [EnrichedIOC(ioc=IOC(type=IOCType.SHA256, value=h),
                         verdict=Verdict.MALICIOUS, confidence=0.9) for h in hashes]
    p = InvestigationPackage(
        investigation_id=inv_id, tenant="t", status=InvestigationStatus.COMPLETE,
        alert=Alert(source=SourceProduct.GENERIC, source_alert_id=inv_id, title=inv_id),
        overall_verdict=verdict, iocs=iocs,
        mitre=[MitreTechnique(technique_id=t, name=t, tactic=_tactic(t))
               for t in techniques],
        affected_users=list(users), affected_hosts=list(hosts))
    if when:
        p.created_at = when
    p.incident_dna = build_fingerprint_engine().compute(p)
    return p


def _tactic(tid: str) -> str:
    return {
        "T1566": "initial-access", "T1059": "execution", "T1547": "persistence",
        "T1003": "credential-access", "T1021": "lateral-movement",
        "T1071": "command-and-control", "T1486": "impact", "T1490": "impact",
        "T1078": "initial-access", "T1105": "command-and-control",
    }.get(tid.split(".")[0], "execution")


# ---------------------------------------------------------------- attribution


def test_ransomware_attribution():
    a = AttributionEngine().attribute(
        techniques={"T1486", "T1490", "T1059.001"},
        tactics={"impact", "execution"}, infra_count=1, malware_count=1,
        identity_count=0, host_count=5)
    assert a.actor_type == "ransomware" and a.confidence >= 0.8
    assert "T1486" in a.signals


def test_apt_attribution_needs_breadth_and_cred_or_lateral():
    a = AttributionEngine().attribute(
        techniques={"T1566", "T1059", "T1547", "T1003", "T1071"},
        tactics={"initial-access", "execution", "persistence",
                 "credential-access", "command-and-control"},
        infra_count=2, malware_count=1, identity_count=1, host_count=4)
    assert a.actor_type == "apt"
    assert any("kill chain" in r for r in a.rationale)


def test_crimeware_attribution_phishing_plus_malware():
    a = AttributionEngine().attribute(
        techniques={"T1566.002", "T1059.001"},
        tactics={"initial-access", "execution"}, infra_count=1, malware_count=1,
        identity_count=2, host_count=1)
    assert a.actor_type == "crimeware"


def test_insider_attribution_no_infra_no_malware():
    a = AttributionEngine().attribute(
        techniques={"T1078"}, tactics={"initial-access"}, infra_count=0,
        malware_count=0, identity_count=1, host_count=1)
    assert a.actor_type == "insider"


def test_never_fabricates_when_signals_are_weak():
    a = AttributionEngine().attribute(
        techniques=set(), tactics=set(), infra_count=0, malware_count=0,
        identity_count=0, host_count=0)
    assert a.actor_type == "unattributed" and a.confidence == 0.0
    assert a.signals == []


def test_ransomware_beats_other_candidates():
    # phishing + malware (crimeware) AND ransomware impact -> ransomware wins.
    a = AttributionEngine().attribute(
        techniques={"T1566", "T1486"}, tactics={"initial-access", "impact"},
        infra_count=1, malware_count=1, identity_count=1, host_count=3)
    assert a.actor_type == "ransomware"
    assert any("alternatives considered" in r for r in a.rationale)


# ---------------------------------------------------------------- clustering


def test_clusters_incidents_sharing_infrastructure():
    now = datetime.now(UTC)
    engine = build_campaign_engine()
    packages = [
        pkg("a", domains=["evil.com"], techniques=["T1566", "T1059"], when=now),
        pkg("b", domains=["evil.com"], techniques=["T1566", "T1547"],
            when=now + timedelta(hours=2)),
        pkg("z", domains=["unrelated.org"], techniques=["T1490"],
            when=now + timedelta(days=1)),
    ]
    clusters = engine.cluster(packages)
    assert len(clusters) == 1  # a & b campaign; z is alone (not a campaign)
    c = clusters[0]
    assert set(c.members) == {"a", "b"}
    assert "evil.com" in c.shared_infrastructure
    assert c.first_seen == now and c.last_seen == now + timedelta(hours=2)
    assert c.attribution.actor_type  # attribution attached to the campaign


def test_single_incident_is_not_a_campaign():
    clusters = build_campaign_engine().cluster([pkg("solo", domains=["x.com"])])
    assert clusters == []


def test_benign_incidents_excluded_from_campaigns():
    packages = [
        pkg("a", domains=["evil.com"], verdict=Verdict.BENIGN),
        pkg("b", domains=["evil.com"], verdict=Verdict.BENIGN),
    ]
    assert build_campaign_engine().cluster(packages) == []


def test_cluster_for_incident():
    engine = build_campaign_engine()
    packages = [pkg("a", domains=["evil.com"], techniques=["T1566"]),
                pkg("b", domains=["evil.com"], techniques=["T1566"])]
    c = engine.cluster_for("a", packages)
    assert c is not None and "a" in c.members
    assert engine.cluster_for("nonexistent", packages) is None


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_investigation_attaches_attribution():
    from tests.test_agents import make_investigator, make_phishing_alert

    p = await make_investigator().investigate("attr-tenant", make_phishing_alert())
    assert p.attribution is not None
    # phishing + dropped malware -> crimeware
    assert p.attribution.actor_type == "crimeware"
    assert any(s.action == "attribution" for s in p.agent_trace)


def test_campaigns_api(client):
    headers = {"X-Tenant-ID": "camp-api", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}

    def ingest(num: str) -> str:
        payload = {"source": "sentinel", "message_id": f"phish-{num}",
                   "properties": {"incidentNumber": f"INC-{num}",
                                  "title": "Phishing email reported",
                                  "description": "hxxps://evil[.]com/pay "
                                                 "Invoice_8841.lnk",
                                  "severity": "high"}}
        r = client.post("/api/v1/alerts/ingest", json=payload, headers=headers)
        assert r.status_code == 201
        return r.json()["investigation_id"]

    a = ingest("1")
    ingest("2")  # same campaign (shared infra + TTP)

    resp = client.get("/api/v1/campaigns", headers=headers)
    assert resp.status_code == 200
    campaigns = resp.json()
    assert campaigns and campaigns[0]["size"] >= 2
    assert campaigns[0]["attribution"]["actor_type"]

    one = client.get(f"/api/v1/campaigns/for/{a}", headers=headers)
    assert one.status_code == 200 and a in one.json()["members"]


def test_campaigns_api_requires_auth(client):
    assert client.get("/api/v1/campaigns").status_code == 401
