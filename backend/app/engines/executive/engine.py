"""Executive intelligence engine — read-only aggregation across investigations.

Computes the board-level metrics (business risk, financial exposure, MTTR, AI
time saved, false-positive rate, campaigns, top actor types, departments,
compliance impact, risk trend) from the investigation packages already produced.
Adds no new storage; reuses the repository, campaign engine and attribution.
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from app.engines.campaign import build_campaign_engine
from app.schemas.common import Severity, Verdict
from app.schemas.executive import (
    ActorCount,
    DepartmentCount,
    ExecutiveSummary,
    RiskTrendPoint,
)
from app.schemas.investigation import InvestigationPackage

# Analyst baseline: a manual triage/investigation of one alert (industry ~hours).
_MANUAL_BASELINE_HOURS = 4.0
_COST_BAND = {
    Severity.CRITICAL: "$100k-$1M+",
    Severity.HIGH: "$10k-$100k",
    Severity.MEDIUM: "$1k-$10k",
    Severity.LOW: "<$1k",
}
_SEV_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}


class ExecutiveEngine:
    def summarize(self, packages: list[InvestigationPackage], *,
                  window_days: int = 30) -> ExecutiveSummary:
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=window_days)
        pkgs = [p for p in packages if _aware(p.created_at) >= cutoff]

        summary = ExecutiveSummary(generated_at=now, window_days=window_days)
        summary.investigation_volume = len(pkgs)
        if not pkgs:
            return summary

        # Volume & quality
        summary.malicious_count = sum(
            1 for p in pkgs if p.overall_verdict is Verdict.MALICIOUS)
        summary.suspicious_count = sum(
            1 for p in pkgs if p.overall_verdict is Verdict.SUSPICIOUS)
        summary.benign_count = sum(
            1 for p in pkgs if p.overall_verdict is Verdict.BENIGN)
        # FP proxy: alerts that resolved benign after automated triage.
        summary.false_positive_rate = round(
            summary.benign_count / len(pkgs), 3)

        # Risk & exposure
        risks = [p.risk.score for p in pkgs if p.risk]
        summary.average_risk_score = round(sum(risks) / len(risks), 1) if risks else 0.0
        summary.business_risk = _risk_level(summary.average_risk_score)
        impacts = [p.business_impact.level for p in pkgs if p.business_impact]
        if impacts:
            worst = min(impacts, key=lambda s: _SEV_RANK[s])
            summary.financial_exposure_band = _COST_BAND.get(worst, "$0")
            summary.high_impact_incidents = sum(
                1 for s in impacts if s in (Severity.CRITICAL, Severity.HIGH))

        # Efficiency
        durations = [(_aware(p.completed_at) - _aware(p.created_at)).total_seconds() / 60
                     for p in pkgs if p.completed_at]
        mean_min = sum(durations) / len(durations) if durations else 0.0
        summary.estimated_mttr_minutes = round(mean_min, 2)
        actual_hours = sum(durations) / 60 if durations else 0.0
        summary.ai_time_saved_hours = round(
            len(pkgs) * _MANUAL_BASELINE_HOURS - actual_hours, 1)
        summary.analyst_productivity_multiplier = round(
            min(5000.0, (_MANUAL_BASELINE_HOURS * 60) / max(mean_min, 0.1)), 1)

        # Threat landscape
        summary.active_campaigns = len(build_campaign_engine().cluster(pkgs))
        actors = Counter(
            p.attribution.actor_type for p in pkgs
            if p.attribution and p.attribution.actor_type != "unattributed")
        summary.top_threat_actors = [
            ActorCount(actor_type=a, count=c) for a, c in actors.most_common(6)]

        dept_counter: Counter[str] = Counter()
        for p in pkgs:
            for dept in _departments(p.affected_hosts):
                dept_counter[dept] += 1
        summary.departments_affected = [
            DepartmentCount(department=d, incidents=c)
            for d, c in dept_counter.most_common(8)]

        summary.compliance_impact = _compliance_flags(pkgs, dept_counter)
        summary.risk_trend = _risk_trend(pkgs)
        return summary


def _aware(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(UTC)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _risk_level(avg: float) -> str:
    if avg >= 70:
        return "critical"
    if avg >= 50:
        return "high"
    if avg >= 30:
        return "medium"
    return "low"


def _departments(hosts: list[str]) -> set[str]:
    depts: set[str] = set()
    for h in hosts:
        u = h.upper()
        if "FIN" in u:
            depts.add("Finance")
        elif u.startswith("DC") or "DOMAIN" in u:
            depts.add("Domain Controllers")
        elif "SRV" in u or "SQL" in u or "SERVER" in u:
            depts.add("Servers / IT")
        elif "HR" in u:
            depts.add("Human Resources")
        elif "ENG" in u or "DEV" in u:
            depts.add("Engineering")
        else:
            depts.add("General Workstations")
    return depts


def _compliance_flags(pkgs: list[InvestigationPackage],
                      dept_counter: Counter[str]) -> list[str]:
    flags: list[str] = []
    if dept_counter.get("Finance"):
        flags.append("Financial reporting exposure (SOX / PCI-DSS)")
    affected_users = sum(len(p.affected_users) for p in pkgs)
    if affected_users >= 5:
        flags.append("Personal-data exposure (GDPR / CCPA)")
    if any(p.business_impact and p.business_impact.level is Severity.CRITICAL
           for p in pkgs):
        flags.append("Critical-asset / crown-jewel involvement")
    return flags


def _risk_trend(pkgs: list[InvestigationPackage]) -> list[RiskTrendPoint]:
    buckets: dict[str, list[float]] = {}
    for p in pkgs:
        day = _aware(p.created_at).date().isoformat()
        buckets.setdefault(day, []).append(p.risk.score if p.risk else 0.0)
    return [
        RiskTrendPoint(period=day, avg_risk=round(sum(v) / len(v), 1), count=len(v))
        for day, v in sorted(buckets.items())
    ]


_engine: ExecutiveEngine | None = None


def build_executive_engine() -> ExecutiveEngine:
    global _engine
    if _engine is None:
        _engine = ExecutiveEngine()
    return _engine
