"""Incident DNA: fingerprint computation, similarity, store, and matching."""
from __future__ import annotations

import pytest

from app.engines.fingerprint import (
    FingerprintEngine,
    InMemoryFingerprintStore,
)
from app.schemas.alert import Alert
from app.schemas.common import (
    InvestigationStatus,
    IOCType,
    SourceProduct,
    Verdict,
)
from app.schemas.investigation import InvestigationPackage, MitreTechnique
from app.schemas.ioc import IOC, EnrichedIOC


def pkg_with(inv_id: str, *, domains=(), hashes=(), techniques=(), users=(),
             verdict=Verdict.MALICIOUS) -> InvestigationPackage:
    iocs: list[EnrichedIOC] = []
    for d in domains:
        iocs.append(EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value=d),
                                verdict=Verdict.MALICIOUS, confidence=0.9))
    for h in hashes:
        iocs.append(EnrichedIOC(ioc=IOC(type=IOCType.SHA256, value=h),
                                verdict=Verdict.MALICIOUS, confidence=0.9))
    return InvestigationPackage(
        investigation_id=inv_id, tenant="t",
        status=InvestigationStatus.COMPLETE,
        alert=Alert(source=SourceProduct.GENERIC, source_alert_id=inv_id, title=inv_id),
        overall_verdict=verdict,
        iocs=iocs,
        mitre=[MitreTechnique(technique_id=t, name=t, tactic="execution")
               for t in techniques],
        affected_users=list(users),
    )


# ---------------------------------------------------------------- compute


def test_compute_produces_all_seven_fingerprints():
    dna = FingerprintEngine().compute(pkg_with(
        "i1", domains=["evil.com"], hashes=["a" * 64], techniques=["T1059.001"],
        users=["jdoe"]))
    kinds = {f.kind for f in dna.fingerprints}
    assert kinds == {"infrastructure", "malware", "ttp", "identity", "threat",
                     "campaign", "incident"}
    # each populated fingerprint has a stable hash
    infra = dna.by_kind("infrastructure")
    assert infra.features == ["evil.com"] and len(infra.hash) == 16


def test_fingerprint_hash_is_stable_and_order_independent():
    a = FingerprintEngine().compute(pkg_with("i1", domains=["a.com", "b.com"]))
    b = FingerprintEngine().compute(pkg_with("i2", domains=["b.com", "a.com"]))
    assert a.by_kind("infrastructure").hash == b.by_kind("infrastructure").hash


def test_empty_dimension_has_empty_hash():
    dna = FingerprintEngine().compute(pkg_with("i1", domains=["evil.com"]))
    assert dna.by_kind("malware").hash == ""  # no malware artifacts


# ---------------------------------------------------------------- similarity


def test_similarity_high_for_shared_infrastructure():
    eng = FingerprintEngine()
    a = eng.compute(pkg_with("i1", domains=["evil.com"], techniques=["T1059.001"]))
    b = eng.compute(pkg_with("i2", domains=["evil.com"], techniques=["T1071.001"]))
    overall, dims, shared = eng.similarity(a, b)
    assert dims["infrastructure"] == 1.0  # identical infra
    assert "evil.com" in shared["infrastructure"]
    assert overall > 0


def test_similarity_zero_for_disjoint_incidents():
    eng = FingerprintEngine()
    a = eng.compute(pkg_with("i1", domains=["a.com"], techniques=["T1059.001"]))
    b = eng.compute(pkg_with("i2", domains=["z.com"], techniques=["T1486"]))
    overall, _dims, shared = eng.similarity(a, b)
    assert overall == 0.0 and shared == {}


# ---------------------------------------------------------------- store + match


def test_match_finds_similar_prior_incident():
    eng = FingerprintEngine()
    store = InMemoryFingerprintStore()
    first = eng.compute(pkg_with("first", domains=["evil.com"],
                                 hashes=["a" * 64], techniques=["T1059.001"]))
    store.store("t", first, "First phishing wave")

    current = eng.compute(pkg_with("current", domains=["evil.com"],
                                   techniques=["T1059.001"]))
    matches = eng.match(current, store.all_for_tenant("t"))
    assert matches and matches[0].investigation_id == "first"
    assert matches[0].title == "First phishing wave"
    assert "infrastructure" in matches[0].dimension_similarity
    assert matches[0].overall_similarity > 0


def test_match_excludes_self_and_dissimilar():
    eng = FingerprintEngine()
    store = InMemoryFingerprintStore()
    dna = eng.compute(pkg_with("self", domains=["evil.com"]))
    store.store("t", dna, "self")
    store.store("t", eng.compute(pkg_with("other", domains=["unrelated.com"])),
                "other")
    matches = eng.match(dna, store.all_for_tenant("t"))
    assert all(m.investigation_id != "self" for m in matches)  # never match self
    assert matches == []  # 'other' shares nothing


def test_store_is_tenant_isolated():
    store = InMemoryFingerprintStore()
    store.store("acme", FingerprintEngine().compute(pkg_with("i1", domains=["x.com"])),
                "t")
    assert store.all_for_tenant("globex") == []
    assert store.get("globex", "i1") is None


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_investigation_generates_and_matches_dna():
    from tests.test_agents import make_investigator, make_phishing_alert

    tenant = "dna-integration"
    agent = make_investigator()
    first = await agent.investigate(tenant, make_phishing_alert())
    assert first.incident_dna is not None
    assert len(first.incident_dna.fingerprints) == 7
    assert first.dna_matches == []  # nothing prior to match

    # A second, same-campaign incident must fingerprint-match the first.
    second = await agent.investigate(
        tenant, make_phishing_alert(source_alert_id="INC-2"))
    ids = {m.investigation_id for m in second.dna_matches}
    assert first.investigation_id in ids
    top = second.dna_matches[0]
    assert top.overall_similarity > 0 and top.shared


@pytest.mark.asyncio
async def test_dna_api(client):
    headers = {"X-Tenant-ID": "dna-api", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    payload = {"source": "generic", "id": "DNA-1", "title": "beacon",
               "raw_text": "45.155.205.99 malware-c2.net"}
    inv = client.post("/api/v1/alerts/ingest", json=payload, headers=headers)
    inv_id = inv.json()["investigation_id"]

    dna = client.get(f"/api/v1/fingerprints/{inv_id}", headers=headers)
    assert dna.status_code == 200
    assert {f["kind"] for f in dna.json()["fingerprints"]} >= {"infrastructure",
                                                               "incident"}

    matches = client.get(f"/api/v1/fingerprints/{inv_id}/matches", headers=headers)
    assert matches.status_code == 200

    missing = client.get("/api/v1/fingerprints/nope", headers=headers)
    assert missing.status_code == 404


def test_dna_api_requires_auth(client):
    assert client.get("/api/v1/fingerprints/x").status_code == 401
