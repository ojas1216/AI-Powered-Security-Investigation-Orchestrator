"""Threat-intelligence dossier: classifier, ThreatFox connector, dossier, API."""
from __future__ import annotations

import pytest

from app.engines.threat_intel.classifier import classify
from app.engines.threat_intel.connectors.threatfox import ThreatFoxConnector
from app.engines.threat_intel.dossier import build_dossier_engine
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC

_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------- classifier


@pytest.mark.parametrize("raw,expected", [
    ("https://evil.com/pay", IOCType.URL),
    ("hxxps://evil[.]com/pay", IOCType.URL),
    ("user@corp.com", IOCType.EMAIL),
    ("45.155.205.99", IOCType.IPV4),
    ("2606:4700:4700::1111", IOCType.IPV6),
    ("192.168.0.0/24", IOCType.CIDR),
    ("AS13335", IOCType.ASN),
    (_SHA, IOCType.SHA256),
    ("a" * 40, IOCType.SHA1),
    ("a" * 32, IOCType.MD5),
    ("t13d1516h2_8daaf6152771_b186095e22b6", IOCType.JA4),
    ("evil-c2.example.com", IOCType.DOMAIN),
    ("evil(dot)com", IOCType.DOMAIN),
])
def test_classifier(raw: str, expected: IOCType):
    assert classify(raw).type is expected


# ---------------------------------------------------------------- threatfox


@pytest.mark.asyncio
async def test_threatfox_offline_known_ioc():
    tf = ThreatFoxConnector()
    rec = await tf.enrich(IOC(type=IOCType.DOMAIN, value="malware-c2.net"))
    assert rec is not None
    assert rec.malware_printable == "QakBot"
    assert "c2" in rec.tags
    assert rec.related  # related IOCs present
    v = await tf.lookup(IOC(type=IOCType.DOMAIN, value="malware-c2.net"))
    assert v.verdict is Verdict.MALICIOUS and v.score >= 0.75


@pytest.mark.asyncio
async def test_threatfox_unknown_ioc_is_unknown():
    tf = ThreatFoxConnector()
    assert await tf.enrich(IOC(type=IOCType.DOMAIN, value="not-in-cache.example")) is None
    v = await tf.lookup(IOC(type=IOCType.DOMAIN, value="not-in-cache.example"))
    assert v.verdict is Verdict.UNKNOWN


# ---------------------------------------------------------------- dossier


@pytest.mark.asyncio
async def test_dossier_for_malicious_domain_is_complete():
    d = await build_dossier_engine().build("malware-c2.net", "dossier-t")
    assert d.ioc_type is IOCType.DOMAIN
    assert d.verdict is Verdict.MALICIOUS and d.risk_score > 60
    # ThreatFox + mock both contributed
    sources = {p.source for p in d.threat_intel}
    assert "threatfox" in sources and len(d.threat_intel) >= 2
    assert any(p.malware_family == "QakBot" for p in d.threat_intel)
    # context sections populated
    assert d.whois and d.whois.registrar and d.whois.age_days is not None
    assert d.dns and d.dns.a
    assert d.hosting and d.hosting.asn
    # relationships from ThreatFox related
    assert "45.155.205.99" in d.relationships.related_ips
    assert _SHA in d.relationships.related_hashes
    # explainability
    assert d.confidence.supporting and d.confidence.rationale
    assert d.timeline.first_seen and d.timeline.last_seen
    assert d.mitre.techniques  # C2 mapped
    assert d.business_impact and d.business_impact.recommended_actions
    assert d.references and d.evidence and d.executive_summary


@pytest.mark.asyncio
async def test_dossier_defang_aware():
    d = await build_dossier_engine().build("malware-c2[.]net", "dossier-t")
    assert d.indicator == "malware-c2.net"
    assert d.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_dossier_hash():
    d = await build_dossier_engine().build(_SHA, "dossier-t")
    assert d.ioc_type is IOCType.SHA256
    assert d.verdict is Verdict.MALICIOUS  # bundled known-bad + threatfox
    assert d.whois is None  # not a domain


@pytest.mark.asyncio
async def test_dossier_failure_isolated(monkeypatch):
    """A provider that raises must not break the dossier."""
    from app.engines.threat_intel.connectors.threatfox import ThreatFoxConnector

    async def boom(self, ioc):
        raise ConnectionError("threatfox down")

    monkeypatch.setattr(ThreatFoxConnector, "enrich", boom)
    monkeypatch.setattr(ThreatFoxConnector, "lookup", boom)
    # rebuild a fresh engine so the patched connector is used
    from app.engines.threat_intel import dossier as dmod
    monkeypatch.setattr(dmod, "_engine", None)
    d = await dmod.build_dossier_engine().build("malware-c2.net", "dossier-t")
    # mock TI still produced a verdict; the dossier is intact
    assert d.verdict is Verdict.MALICIOUS
    assert all(p.source != "threatfox" for p in d.threat_intel)


@pytest.mark.asyncio
async def test_dossier_correlates_with_prior_incident():
    """After an investigation stored its DNA, a dossier for one of its IOCs must
    correlate back to it."""
    from tests.test_agents import make_investigator, make_phishing_alert

    tenant = "dossier-campaign"
    pkg = await make_investigator().investigate(tenant, make_phishing_alert())
    d = await build_dossier_engine().build("malware-c2.net", tenant)
    ids = {m.investigation_id for m in d.campaign_matches}
    assert pkg.investigation_id in ids
    assert pkg.investigation_id in d.relationships.campaigns


# ---------------------------------------------------------------- API


def test_dossier_api(client):
    headers = {"X-Tenant-ID": "intel-api", "X-Roles": "tier1_analyst",
               "Authorization": "Bearer dev"}
    resp = client.post("/api/v1/intel/dossier",
                       json={"indicator": "malware-c2.net"}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "malicious"
    assert body["ioc_type"] == "domain"
    assert any(p["source"] == "threatfox" for p in body["threat_intel"])


def test_dossier_api_requires_auth(client):
    assert client.post("/api/v1/intel/dossier",
                       json={"indicator": "x"}).status_code == 401
