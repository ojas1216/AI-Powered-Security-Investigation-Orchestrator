"""Multi-format detection engineering: generators, metadata, API."""
from __future__ import annotations

from app.engines.detection_export import build_detection_export_engine
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, IOCType, SourceProduct, Verdict
from app.schemas.investigation import InvestigationPackage, MitreTechnique
from app.schemas.ioc import IOC, EnrichedIOC

_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def pkg() -> InvestigationPackage:
    iocs = [
        EnrichedIOC(ioc=IOC(type=IOCType.IPV4, value="45.155.205.99"),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
        EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="evil.com"),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
        EnrichedIOC(ioc=IOC(type=IOCType.SHA256, value=_SHA),
                    verdict=Verdict.MALICIOUS, confidence=0.9),
        EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="benign.com"),
                    verdict=Verdict.BENIGN, confidence=0.1),  # excluded
    ]
    return InvestigationPackage(
        investigation_id="i1", tenant="t", status=InvestigationStatus.COMPLETE,
        alert=Alert(source=SourceProduct.GENERIC, source_alert_id="INC-1",
                    title="Phishing C2"),
        overall_verdict=Verdict.MALICIOUS, iocs=iocs,
        mitre=[MitreTechnique(technique_id="T1071.001", name="C2",
                              tactic="command-and-control")])


def test_generates_all_expected_formats():
    rules = build_detection_export_engine().generate(pkg())
    formats = {r.format for r in rules}
    assert {"sigma", "yara", "suricata", "splunk_spl", "sentinel_kql",
            "chronicle_yaral", "elastic_eql", "wazuh", "falcon"} <= formats


def test_every_rule_has_metadata():
    for r in build_detection_export_engine().generate(pkg()):
        assert r.rule.strip()
        assert r.rationale
        assert 0 <= r.estimated_precision <= 1
        assert 0 <= r.estimated_recall <= 1


def test_rules_are_grounded_in_malicious_iocs_only():
    rules = {r.format: r for r in build_detection_export_engine().generate(pkg())}
    # confirmed IOCs appear; the benign domain never does
    for fmt in ("suricata", "splunk_spl", "sentinel_kql", "elastic_eql", "falcon"):
        assert "45.155.205.99" in rules[fmt].rule
        assert "evil.com" in rules[fmt].rule
        assert "benign.com" not in rules[fmt].rule


def test_yara_only_when_hashes_present():
    rules = {r.format: r for r in build_detection_export_engine().generate(pkg())}
    assert "yara" in rules and _SHA in rules["yara"].rule

    no_hash = pkg()
    no_hash.iocs = [e for e in no_hash.iocs if e.ioc.type is not IOCType.SHA256]
    fmts = {r.format for r in build_detection_export_engine().generate(no_hash)}
    assert "yara" not in fmts  # nothing to hash-match
    assert "suricata" in fmts  # network formats still generated


def test_hash_rule_high_precision_low_recall():
    yara = next(r for r in build_detection_export_engine().generate(pkg())
                if r.format == "yara")
    assert yara.estimated_precision >= 0.9
    assert yara.estimated_recall <= 0.4  # specific to the sample


def test_benign_investigation_yields_behavioral_only():
    p = pkg()
    p.overall_verdict = Verdict.BENIGN
    p.iocs = [EnrichedIOC(ioc=IOC(type=IOCType.DOMAIN, value="x.com"),
                          verdict=Verdict.BENIGN, confidence=0.1)]
    rules = build_detection_export_engine().generate(p)
    # no malicious IOCs -> no network/hash formats, only the sigma (behavioral)
    formats = {r.format for r in rules}
    assert formats == {"sigma"}


# ---------------------------------------------------------------- API


def test_export_api(client):
    headers = {"X-Tenant-ID": "exp-api", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    payload = {"source": "sentinel", "message_id": "phish-exp",
               "properties": {"incidentNumber": "INC-EXP",
                              "title": "Phishing email reported",
                              "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
                              "severity": "high"}}
    inv = client.post("/api/v1/alerts/ingest", json=payload, headers=headers)
    inv_id = inv.json()["investigation_id"]

    resp = client.get(f"/api/v1/detections/export/{inv_id}", headers=headers)
    assert resp.status_code == 200
    formats = {r["format"] for r in resp.json()}
    assert {"sigma", "suricata", "sentinel_kql", "falcon"} <= formats
    assert all("estimated_precision" in r for r in resp.json())


def test_export_requires_permission(client):
    assert client.get("/api/v1/detections/export/x").status_code == 401
