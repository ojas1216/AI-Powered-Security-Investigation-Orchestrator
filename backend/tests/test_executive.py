"""Executive intelligence: aggregate metrics engine + API."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.engines.executive import build_executive_engine
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, Severity, SourceProduct, Verdict
from app.schemas.investigation import (
    Attribution,
    BusinessImpact,
    InvestigationPackage,
    RiskBreakdown,
)


def pkg(inv_id: str, *, verdict=Verdict.MALICIOUS, risk=75.0, hosts=(),
        users=(), actor="crimeware", impact=Severity.HIGH,
        created=None, duration_min=0.01) -> InvestigationPackage:
    created = created or datetime.now(UTC)
    return InvestigationPackage(
        investigation_id=inv_id, tenant="t", status=InvestigationStatus.COMPLETE,
        alert=Alert(source=SourceProduct.GENERIC, source_alert_id=inv_id, title=inv_id),
        overall_verdict=verdict,
        risk=RiskBreakdown(score=risk, severity=Severity.HIGH),
        business_impact=BusinessImpact(level=impact),
        attribution=Attribution(actor_type=actor, confidence=0.6),
        affected_hosts=list(hosts), affected_users=list(users),
        created_at=created,
        completed_at=created + timedelta(minutes=duration_min))


def test_empty_window_is_zeroed():
    s = build_executive_engine().summarize([])
    assert s.investigation_volume == 0 and s.average_risk_score == 0.0


def test_volume_verdicts_and_fp_rate():
    pkgs = [pkg("a"), pkg("b"), pkg("c", verdict=Verdict.BENIGN, risk=5.0)]
    s = build_executive_engine().summarize(pkgs)
    assert s.investigation_volume == 3
    assert s.malicious_count == 2 and s.benign_count == 1
    assert s.false_positive_rate == round(1 / 3, 3)


def test_risk_and_financial_exposure():
    pkgs = [pkg("a", risk=90.0, impact=Severity.CRITICAL),
            pkg("b", risk=60.0, impact=Severity.MEDIUM)]
    s = build_executive_engine().summarize(pkgs)
    assert s.average_risk_score == 75.0
    assert s.business_risk == "critical"
    assert s.financial_exposure_band == "$100k-$1M+"  # worst present
    assert s.high_impact_incidents == 1  # the critical one


def test_efficiency_metrics():
    pkgs = [pkg("a", duration_min=0.02), pkg("b", duration_min=0.02)]
    s = build_executive_engine().summarize(pkgs)
    # 2 investigations * 4h manual baseline ≈ 8h saved (actual is negligible)
    assert 7.9 <= s.ai_time_saved_hours <= 8.0
    assert s.estimated_mttr_minutes > 0
    assert s.analyst_productivity_multiplier > 1


def test_threat_landscape_and_departments():
    pkgs = [
        pkg("a", actor="ransomware", hosts=["WS-FIN-1"], users=["u1", "u2", "u3"]),
        pkg("b", actor="ransomware", hosts=["DC-01"]),
        pkg("c", actor="crimeware", hosts=["WS-ENG-9"], users=["u4", "u5"]),
    ]
    s = build_executive_engine().summarize(pkgs)
    actors = {a.actor_type: a.count for a in s.top_threat_actors}
    assert actors["ransomware"] == 2 and actors["crimeware"] == 1
    depts = {d.department for d in s.departments_affected}
    assert "Finance" in depts and "Domain Controllers" in depts
    # 5 affected users total -> GDPR/CCPA flag; finance -> SOX/PCI; critical? no
    assert any("GDPR" in c for c in s.compliance_impact)
    assert any("SOX" in c for c in s.compliance_impact)


def test_unattributed_excluded_from_top_actors():
    s = build_executive_engine().summarize([pkg("a", actor="unattributed")])
    assert s.top_threat_actors == []


def test_risk_trend_buckets_by_day():
    day1 = datetime(2026, 7, 10, tzinfo=UTC)
    day2 = datetime(2026, 7, 11, tzinfo=UTC)
    pkgs = [pkg("a", risk=80, created=day1), pkg("b", risk=60, created=day1),
            pkg("c", risk=40, created=day2)]
    s = build_executive_engine().summarize(pkgs, window_days=3650)
    trend = {t.period: (t.avg_risk, t.count) for t in s.risk_trend}
    assert trend["2026-07-10"] == (70.0, 2)
    assert trend["2026-07-11"] == (40.0, 1)


def test_window_filters_old_incidents():
    old = datetime.now(UTC) - timedelta(days=60)
    s = build_executive_engine().summarize(
        [pkg("recent"), pkg("old", created=old)], window_days=30)
    assert s.investigation_volume == 1  # the 60-day-old one is excluded


# ---------------------------------------------------------------- API


def test_executive_api(client):
    headers = {"X-Tenant-ID": "exec-api", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    payload = {"source": "sentinel", "message_id": "phish-exec",
               "properties": {"incidentNumber": "INC-EXEC",
                              "title": "Phishing email reported",
                              "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
                              "severity": "high"}}
    assert client.post("/api/v1/alerts/ingest", json=payload,
                       headers=headers).status_code == 201

    # A SOC manager (read-only) views the executive summary.
    manager = {"X-Tenant-ID": "exec-api", "X-Roles": "soc_manager",
               "Authorization": "Bearer dev"}
    resp = client.get("/api/v1/executive/summary", headers=manager)
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigation_volume"] >= 1
    assert body["ai_time_saved_hours"] > 0
    assert "business_risk" in body and "risk_trend" in body


def test_executive_api_requires_auth(client):
    assert client.get("/api/v1/executive/summary").status_code == 401
