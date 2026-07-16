"""Knowledge-graph query tests: neighbors, campaign detection, attack path."""
from __future__ import annotations

from app.engines.graph.client import GraphTriple, InMemoryGraph, node_type


def seed_two_alerts_sharing_c2(g: InMemoryGraph, tenant: str) -> None:
    """Two alerts that reuse the same C2 domain on two hosts — a campaign."""
    g.upsert(tenant, [
        GraphTriple("alert:INC-1", "contains", "domain:evil.com"),
        GraphTriple("host:WS-1", "affected_by", "alert:INC-1"),
        GraphTriple("alert:INC-2", "contains", "domain:evil.com"),
        GraphTriple("host:WS-2", "affected_by", "alert:INC-2"),
        GraphTriple("alert:INC-2", "contains", "ipv4:45.155.205.99"),
    ])


def test_upsert_is_idempotent():
    g = InMemoryGraph()
    t = [GraphTriple("a", "rel", "b")]
    g.upsert("acme", t)
    res = g.upsert("acme", t)  # same edge again
    assert len(res.edges) == 1
    assert res.nodes == ["a", "b"]


def test_neighbors_depth_expands_subgraph():
    g = InMemoryGraph()
    seed_two_alerts_sharing_c2(g, "acme")

    one = g.neighbors("acme", "domain:evil.com", depth=1)
    assert set(one.nodes) == {"domain:evil.com", "alert:INC-1", "alert:INC-2"}

    two = g.neighbors("acme", "domain:evil.com", depth=2)
    assert "host:WS-1" in two.nodes and "host:WS-2" in two.nodes
    assert "ipv4:45.155.205.99" in two.nodes


def test_neighbors_unknown_node_is_empty():
    g = InMemoryGraph()
    seed_two_alerts_sharing_c2(g, "acme")
    assert g.neighbors("acme", "domain:nope.com").nodes == []


def test_campaign_detects_shared_infrastructure():
    g = InMemoryGraph()
    seed_two_alerts_sharing_c2(g, "acme")
    camp = g.campaign("acme", "domain:evil.com", depth=2)
    assert camp.alerts == ["alert:INC-1", "alert:INC-2"]  # both alerts recovered
    assert "host:WS-1" in camp.related_entities
    assert "ipv4:45.155.205.99" in camp.related_entities
    assert camp.seed not in camp.related_entities


def test_attack_path_between_hosts():
    g = InMemoryGraph()
    seed_two_alerts_sharing_c2(g, "acme")
    # WS-1 and WS-2 are linked only through the shared C2 domain.
    path = g.path("acme", "host:WS-1", "host:WS-2")
    assert path, "a path should exist via the shared C2"
    keys = {e.src for e in path} | {e.dst for e in path}
    assert "domain:evil.com" in keys
    # shortest path: WS-1 - INC-1 - evil.com - INC-2 - WS-2 = 4 edges
    assert len(path) == 4


def test_path_absent_returns_empty():
    g = InMemoryGraph()
    g.upsert("acme", [GraphTriple("host:A", "affected_by", "alert:X")])
    g.upsert("acme", [GraphTriple("host:B", "affected_by", "alert:Y")])
    assert g.path("acme", "host:A", "host:B") == []


def test_graph_is_tenant_isolated():
    g = InMemoryGraph()
    seed_two_alerts_sharing_c2(g, "acme")
    assert g.neighbors("globex", "domain:evil.com").nodes == []
    assert g.campaign("globex", "domain:evil.com").alerts == []


def test_node_type_prefix():
    assert node_type("domain:evil.com") == "domain"
    assert node_type("alert:INC-1") == "alert"
    assert node_type("bare") == "entity"


# ---------------------------------------------------------------- API


def _headers(tenant: str = "graph-api-tenant") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "tier3_analyst",
            "Authorization": "Bearer dev"}


def _ingest_phish(client, tenant: str) -> str:
    payload = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-GRAPH-1",
            "title": "Phishing email reported",
            "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
            "severity": "high",
        },
        "message_id": "phish-graph-1",
    }
    r = client.post("/api/v1/alerts/ingest", json=payload, headers=_headers(tenant))
    assert r.status_code == 201
    return r.json()["alert"]["source_alert_id"]


def test_graph_neighbors_api_reflects_investigation(client):
    tenant = "graph-api-neighbors"
    _ingest_phish(client, tenant)
    # The alert node is written as alert:<source_alert_id>.
    resp = client.get("/api/v1/graph/neighbors",
                      params={"node": "alert:INC-GRAPH-1", "depth": 2},
                      headers=_headers(tenant))
    assert resp.status_code == 200, resp.text
    node_keys = {n["key"] for n in resp.json()["nodes"]}
    assert "alert:INC-GRAPH-1" in node_keys
    # at least one enriched IOC hangs off the alert
    assert any(n.startswith(("domain:", "url:", "ipv4:")) for n in node_keys)


def test_graph_campaign_api_requires_auth(client):
    assert client.get("/api/v1/graph/campaign",
                      params={"node": "domain:evil.com"}).status_code == 401


def test_graph_path_404_when_absent(client):
    tenant = "graph-api-path"
    _ingest_phish(client, tenant)
    resp = client.get("/api/v1/graph/path",
                      params={"src": "host:UNKNOWN-A", "dst": "host:UNKNOWN-B"},
                      headers=_headers(tenant))
    assert resp.status_code == 404
