"""API tests for the detection-engineering and threat-hunting surfaces."""
from __future__ import annotations


def hunter_headers(tenant: str = "acme") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "threat_hunter",
            "Authorization": "Bearer dev"}


def tier1_headers(tenant: str = "acme") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "tier1_analyst",
            "Authorization": "Bearer dev"}


# ---------------------------------------------------------------- detections


def test_list_rules_requires_auth(client):
    assert client.get("/api/v1/detections/rules").status_code == 401


def test_list_rules_returns_builtin_catalog(client, auth_headers):
    resp = client.get("/api/v1/detections/rules", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    ids = {r["id"] for r in body["builtin"]}
    assert "AEG-1001" in ids and len(ids) >= 8


def test_custom_rule_lifecycle_and_dry_run(client, auth_headers):
    rule = {
        "id": "ACME-0001",
        "title": "Acme canary token access",
        "severity": "high",
        "condition": {
            "all": [{"field": "raw_text", "modifier": "contains",
                     "values": ["canary-acme-7f3"]}],
        },
        "techniques": [{"technique_id": "T1530",
                        "name": "Data from Cloud Storage", "tactic": "collection"}],
    }
    created = client.put("/api/v1/detections/rules", json=rule, headers=auth_headers)
    assert created.status_code == 201, created.text

    # Dry-run: the custom rule fires alongside builtins, no side effects.
    dry = client.post("/api/v1/detections/evaluate", headers=auth_headers,
                      json={"source": "generic", "id": "X-1", "title": "t",
                            "raw_text": "GET /canary-acme-7f3 from 10.1.1.1"})
    assert dry.status_code == 200
    assert "ACME-0001" in {m["rule_id"] for m in dry.json()}

    # Tenant isolation: another tenant neither sees nor matches the rule.
    other = {"X-Tenant-ID": "globex", "X-Roles": "tier3_analyst",
             "Authorization": "Bearer dev"}
    listed = client.get("/api/v1/detections/rules", headers=other)
    assert all(r["id"] != "ACME-0001" for r in listed.json()["custom"])

    deleted = client.delete("/api/v1/detections/rules/ACME-0001",
                            headers=auth_headers)
    assert deleted.status_code == 204
    assert client.delete("/api/v1/detections/rules/ACME-0001",
                         headers=auth_headers).status_code == 404


def test_custom_rule_cannot_shadow_builtin(client, auth_headers):
    rule = {
        "id": "AEG-1001", "title": "shadowing attempt", "severity": "low",
        "condition": {"all": [{"field": "raw_text", "values": ["x"]}]},
    }
    resp = client.put("/api/v1/detections/rules", json=rule, headers=auth_headers)
    assert resp.status_code == 409


def test_malformed_rule_rejected(client, auth_headers):
    rule = {
        "id": "ACME-BAD", "title": "bad regex", "severity": "low",
        "condition": {"all": [{"field": "raw_text", "modifier": "regex",
                               "values": ["[unclosed"]}]},
    }
    resp = client.put("/api/v1/detections/rules", json=rule, headers=auth_headers)
    assert resp.status_code == 422


def test_rule_write_requires_permission(client):
    rule = {
        "id": "ACME-0002", "title": "tier1 cannot write rules", "severity": "low",
        "condition": {"all": [{"field": "raw_text", "values": ["x"]}]},
    }
    resp = client.put("/api/v1/detections/rules", json=rule,
                      headers=tier1_headers())
    assert resp.status_code == 403


# ---------------------------------------------------------------- hunts


def test_hunt_enriches_and_finds_edr_hits(client):
    resp = client.post("/api/v1/hunts", headers=hunter_headers(),
                       json={"indicators": ["malware-c2.net", "8.8.8.8"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    verdicts = {i["ioc"]["value"]: i["verdict"] for i in body["iocs"]}
    assert verdicts["malware-c2.net"] == "malicious"
    assert body["affected_hosts"] == ["WS-FIN-042"]


def test_hunt_accepts_defanged_free_text(client):
    resp = client.post("/api/v1/hunts", headers=hunter_headers(),
                       json={"text": "seen beaconing to hxxps://evil[.]com/pay"})
    assert resp.status_code == 200
    assert any(i["verdict"] == "malicious" for i in resp.json()["iocs"])


def test_hunt_requires_hunt_permission(client):
    resp = client.post("/api/v1/hunts", headers=tier1_headers(),
                       json={"indicators": ["evil.com"]})
    assert resp.status_code == 403


def test_hunt_with_no_indicators_is_422(client):
    resp = client.post("/api/v1/hunts", headers=hunter_headers(),
                       json={"text": "nothing indicator-like here"})
    assert resp.status_code == 422


def test_hunt_recalls_related_cases_from_memory(client, auth_headers):
    """After an investigation runs, hunting the same IOC surfaces the case."""
    payload = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-HUNT-1",
            "title": "Phishing email reported",
            "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
            "severity": "high",
        },
        "message_id": "phish-hunt-1",
    }
    ingested = client.post("/api/v1/alerts/ingest", json=payload,
                           headers=auth_headers)
    assert ingested.status_code == 201
    inv_id = ingested.json()["investigation_id"]

    resp = client.post("/api/v1/hunts", headers=hunter_headers(),
                       json={"indicators": ["evil.com"]})
    related_ids = {r["investigation_id"]
                   for r in resp.json()["related_investigations"]}
    assert inv_id in related_ids

    # Cross-tenant: globex hunter must not see acme's case.
    resp = client.post("/api/v1/hunts", headers=hunter_headers("globex"),
                       json={"indicators": ["evil.com"]})
    assert resp.json()["related_investigations"] == []
