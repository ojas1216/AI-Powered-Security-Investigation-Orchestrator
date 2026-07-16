"""Semantic memory: embedder determinism, vector store, NL case search."""
from __future__ import annotations

import pytest

from app.engines.semantic import (
    HashingEmbedder,
    InMemoryVectorStore,
    cosine,
)
from app.engines.semantic.embedder import _tokens
from app.engines.semantic.index import CaseIndex
from app.engines.semantic.store import VectorRecord

# ---------------------------------------------------------------- embedder


def test_hashing_embedder_is_deterministic_and_unit_length():
    e = HashingEmbedder(dim=128)
    v1 = e.embed("powershell encoded command on finance host")
    v2 = e.embed("powershell encoded command on finance host")
    assert v1 == v2  # stable across calls (blake2b, not salted hash())
    assert len(v1) == 128
    assert abs(sum(x * x for x in v1) - 1.0) < 1e-9  # L2-normalized


def test_cosine_orders_by_lexical_semantic_overlap():
    e = HashingEmbedder(dim=512)
    q = e.embed("ransomware deleting volume shadow copies")
    near = e.embed("vssadmin delete shadows ransomware impact")
    far = e.embed("benign newsletter subscription confirmation email")
    assert cosine(q, near) > cosine(q, far)


def test_empty_text_embeds_to_zero_vector():
    assert set(HashingEmbedder(dim=16).embed("")) == {0.0}


def test_tokens_include_word_and_trigrams():
    toks = _tokens("evil.com")
    assert "evil.com" in toks
    assert any(len(t) == 3 for t in toks)  # trigrams present


# ---------------------------------------------------------------- store


def test_vector_store_ranks_and_is_tenant_isolated():
    e = HashingEmbedder(dim=256)
    store = InMemoryVectorStore()
    store.add(VectorRecord("c1", "acme", "phishing invoice payment lure",
                           e.embed("phishing invoice payment lure")))
    store.add(VectorRecord("c2", "acme", "brute force ssh login failures",
                           e.embed("brute force ssh login failures")))
    store.add(VectorRecord("x", "globex", "phishing invoice payment",
                           e.embed("phishing invoice payment")))

    hits = store.search("acme", e.embed("fraudulent invoice phishing"), limit=5)
    assert hits[0].record.id == "c1"  # closest match ranks first
    assert {h.record.tenant for h in hits} == {"acme"}  # no cross-tenant leakage


def test_vector_store_upsert_by_id():
    store = InMemoryVectorStore()
    store.add(VectorRecord("c1", "acme", "v1", [1.0, 0.0]))
    store.add(VectorRecord("c1", "acme", "v2", [0.0, 1.0]))
    hits = store.search("acme", [0.0, 1.0], limit=5)
    assert len(hits) == 1 and hits[0].record.text == "v2"


# ---------------------------------------------------------------- index


def _index() -> CaseIndex:
    return CaseIndex(HashingEmbedder(dim=512), InMemoryVectorStore())


@pytest.mark.asyncio
async def test_index_and_search_completed_case():
    from app.orchestrator.investigation import InvestigationOrchestrator
    from tests.test_agents import make_phishing_alert

    idx = _index()
    orch = InvestigationOrchestrator()
    orch.agent.case_index = idx  # inject the isolated index
    pkg = await orch.investigate("sem-acme", make_phishing_alert())

    hits = idx.search("sem-acme", "phishing invoice payment link", limit=5)
    assert hits and hits[0].investigation_id == pkg.investigation_id
    assert hits[0].verdict == "malicious"
    assert hits[0].snippet

    # tenant isolation
    assert idx.search("someone-else", "phishing invoice") == []
    # empty query -> no results
    assert idx.search("sem-acme", "   ") == []


# ---------------------------------------------------------------- API


def _headers(tenant: str) -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "tier3_analyst",
            "Authorization": "Bearer dev"}


def test_case_search_api_end_to_end(client):
    tenant = "sem-api-tenant"
    payload = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-SEM-1",
            "title": "Phishing email reported by finance",
            "description": "hxxps://evil[.]com/pay Invoice_8841.lnk on WS-FIN-042",
            "severity": "high",
        },
        "message_id": "phish-sem-1",
    }
    ingested = client.post("/api/v1/alerts/ingest", json=payload,
                           headers=_headers(tenant))
    assert ingested.status_code == 201
    inv_id = ingested.json()["investigation_id"]

    resp = client.post("/api/v1/search/cases",
                       json={"query": "invoice phishing against finance"},
                       headers=_headers(tenant))
    assert resp.status_code == 200, resp.text
    ids = {h["investigation_id"] for h in resp.json()}
    assert inv_id in ids

    # cross-tenant isolation at the API
    other = client.post("/api/v1/search/cases",
                        json={"query": "invoice phishing"},
                        headers=_headers("sem-api-other"))
    assert all(h["investigation_id"] != inv_id for h in other.json())


def test_case_search_requires_auth(client):
    assert client.post("/api/v1/search/cases",
                       json={"query": "x"}).status_code == 401
