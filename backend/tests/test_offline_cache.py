"""Offline dataset caches: ATT&CK / CVE / Sigma bundled seed + API + Sigma import."""
from __future__ import annotations

from app.engines.offline_cache import build_offline_datasets

# ---------------------------------------------------------------- datasets


def test_bundled_datasets_load_offline():
    ds = build_offline_datasets()
    assert ds.attack.count() >= 30
    assert ds.cve.count() >= 5
    assert ds.sigma.count() >= 4
    # all loaded from the bundle with no cache dir present
    assert all(s.loaded_from == "bundled" for s in ds.statuses())


def test_attack_lookup():
    ds = build_offline_datasets()
    t = ds.attack.get("t1059.001")  # case-insensitive
    assert t is not None
    assert t.name == "PowerShell" and t.tactic == "execution"
    assert ds.attack.get("T9999") is None


def test_cve_lookup_known_vulns():
    ds = build_offline_datasets()
    log4shell = ds.cve.get("cve-2021-44228")
    assert log4shell is not None
    assert log4shell.cvss == 10.0 and log4shell.severity == "critical"
    assert "Log4Shell" in log4shell.summary or "Log4j" in log4shell.summary


def test_sigma_pack_converts_to_valid_detection_rules():
    rules = build_offline_datasets().sigma.as_detection_rules()
    assert len(rules) >= 4
    ids = {r.id for r in rules}
    assert "SIGMA-LSASS-DUMP-COMSVCS" in ids
    # every converted rule carries an ATT&CK mapping and is a valid DetectionRule
    for r in rules:
        assert r.techniques and r.condition.all


def test_sigma_rule_actually_detects():
    """A converted Sigma rule must fire through the real detection engine."""
    from app.engines.detection import DetectionEngine
    from app.schemas.alert import Alert
    from app.schemas.common import SourceProduct

    engine = DetectionEngine(build_offline_datasets().sigma.as_detection_rules())
    alert = Alert(source=SourceProduct.GENERIC, source_alert_id="A-1",
                  title="t", raw_text="rundll32 comsvcs.dll,MiniDump 660 out.dmp full")
    fired = {m.rule_id for m in engine.evaluate(alert)}
    assert "SIGMA-LSASS-DUMP-COMSVCS" in fired


# ---------------------------------------------------------------- API


def _headers(role: str = "tier3_analyst") -> dict[str, str]:
    return {"X-Tenant-ID": "acme", "X-Roles": role, "Authorization": "Bearer dev"}


def test_offline_status_api(client):
    resp = client.get("/api/v1/offline/status", headers=_headers())
    assert resp.status_code == 200
    names = {d["name"] for d in resp.json()}
    assert names == {"attack", "cve", "sigma"}


def test_offline_attack_and_cve_lookup_api(client):
    a = client.get("/api/v1/offline/attack/T1486", headers=_headers())
    assert a.status_code == 200 and a.json()["name"] == "Data Encrypted for Impact"

    c = client.get("/api/v1/offline/cve/CVE-2020-1472", headers=_headers())
    assert c.status_code == 200 and "Zerologon" in c.json()["summary"]

    assert client.get("/api/v1/offline/cve/CVE-0000-0000",
                      headers=_headers()).status_code == 404


def test_offline_sigma_api(client):
    resp = client.get("/api/v1/offline/sigma", headers=_headers())
    assert resp.status_code == 200
    assert len(resp.json()) >= 4


def test_offline_requires_auth(client):
    assert client.get("/api/v1/offline/status").status_code == 401


def test_refresh_requires_write_permission(client):
    # tier1 lacks detection:write
    tier1 = client.post("/api/v1/offline/refresh/cve", headers=_headers("tier1_analyst"))
    assert tier1.status_code == 403


def test_refresh_unknown_dataset_404(client):
    resp = client.post("/api/v1/offline/refresh/nope", headers=_headers())
    assert resp.status_code == 404
