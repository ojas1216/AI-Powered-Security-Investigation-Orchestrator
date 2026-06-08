"""API-surface tests: health, ingestion, authz, multi-tenant isolation."""
from __future__ import annotations


def test_healthz(client):
    resp = client.get("/api/v1/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_security_headers_present(client):
    resp = client.get("/api/v1/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


def test_ingest_requires_auth(client):
    # No dev-bypass headers and no bearer → unauthenticated.
    resp = client.post("/api/v1/alerts/ingest", json={"source": "generic"})
    assert resp.status_code == 401


def test_ingest_runs_investigation(client, auth_headers):
    payload = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-1",
            "title": "Phishing email reported",
            "description": "hxxps://evil[.]com/pay Invoice_8841.lnk WS-FIN-042",
            "severity": "high",
            "entities": [{"kind": "Host", "hostName": "WS-FIN-042"}],
        },
        "message_id": "phish-1",
    }
    resp = client.post("/api/v1/alerts/ingest", json=payload, headers=auth_headers)
    assert resp.status_code == 201
    body = resp.json()
    assert body["overall_verdict"] == "malicious"
    assert body["tenant"] == "acme"


def test_tenant_isolation(client, auth_headers):
    # Create under acme.
    payload = {"source": "generic", "id": "A-1", "title": "test",
               "raw_text": "45.155.205.99"}
    created = client.post("/api/v1/alerts/ingest", json=payload, headers=auth_headers)
    inv_id = created.json()["investigation_id"]

    # Another tenant must not read it (anti-IDOR).
    other = {"X-Tenant-ID": "globex", "X-Roles": "tier3_analyst",
             "Authorization": "Bearer dev"}
    resp = client.get(f"/api/v1/investigations/{inv_id}", headers=other)
    assert resp.status_code == 404


def test_rbac_tier1_cannot_ingest(client):
    headers = {"X-Tenant-ID": "acme", "X-Roles": "tier1_analyst",
               "Authorization": "Bearer dev"}
    resp = client.post("/api/v1/alerts/ingest", json={"source": "generic"}, headers=headers)
    assert resp.status_code == 403


def test_ioc_extract_endpoint(client, auth_headers):
    resp = client.post(
        "/api/v1/iocs/extract",
        json={"text": "reach hxxps://evil[.]com/pay from 45.155.205.99", "enrich": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    values = {item["ioc"]["value"] for item in resp.json()}
    assert "evil.com" in values
