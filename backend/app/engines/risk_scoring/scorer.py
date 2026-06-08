"""Explainable, weighted risk scoring.

Score is 0..100, decomposed into named factors so the analyst (and the copilot)
can see *why*. Inputs come from the rest of the investigation, not a black box.

Factors & weights (sum of weights = 1.0):
  threat_intel   0.30  worst/representative IOC malice + confidence
  sandbox        0.20  detonation malscore
  edr_evidence   0.20  confirmed on-host activity is the strongest signal
  mitre          0.15  presence & severity of ATT&CK techniques
  asset          0.10  criticality of affected assets/users
  email_blast    0.05  breadth of recipients (campaign scale)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.common import Severity, Verdict
from app.schemas.investigation import MitreTechnique, RiskBreakdown
from app.schemas.ioc import EnrichedIOC

_WEIGHTS = {
    "threat_intel": 0.30,
    "sandbox": 0.20,
    "edr_evidence": 0.20,
    "mitre": 0.15,
    "asset": 0.10,
    "email_blast": 0.05,
}

# A few high-severity techniques that should push score up when present.
_HIGH_SEV_TECHNIQUES = {
    "T1486",  # Data Encrypted for Impact (ransomware)
    "T1490",  # Inhibit System Recovery
    "T1003",  # OS Credential Dumping
    "T1071",  # Application Layer Protocol (C2)
    "T1547",  # Boot or Logon Autostart (persistence)
}


@dataclass
class RiskInputs:
    enriched_iocs: list[EnrichedIOC] = field(default_factory=list)
    sandbox_malscore: float = 0.0  # 0..1
    edr_confirmed_hits: int = 0
    mitre: list[MitreTechnique] = field(default_factory=list)
    asset_criticality: float = 0.3  # 0..1 (crown jewel = 1.0)
    recipient_count: int = 0


def _severity_for(score: float) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 55:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


class RiskScorer:
    def score(self, inp: RiskInputs) -> RiskBreakdown:
        factors: dict[str, float] = {}
        rationale: list[str] = []

        # Threat intel: representative = max malice among malicious/suspicious IOCs.
        ti_vals = [
            e.confidence
            for e in inp.enriched_iocs
            if e.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        ]
        ti = max(ti_vals) if ti_vals else 0.0
        factors["threat_intel"] = ti
        if ti_vals:
            n_mal = sum(1 for e in inp.enriched_iocs if e.verdict is Verdict.MALICIOUS)
            rationale.append(
                f"{n_mal} malicious / {len(inp.enriched_iocs)} IOCs corroborated by threat intel"
            )

        factors["sandbox"] = min(1.0, inp.sandbox_malscore)
        if inp.sandbox_malscore > 0.5:
            rationale.append(f"Sandbox detonation malscore {inp.sandbox_malscore:.2f}")

        edr = min(1.0, inp.edr_confirmed_hits / 3.0)
        factors["edr_evidence"] = edr
        if inp.edr_confirmed_hits:
            rationale.append(
                f"{inp.edr_confirmed_hits} confirmed IOC hit(s) in EDR telemetry"
            )

        if inp.mitre:
            high = sum(1 for t in inp.mitre if t.technique_id.split(".")[0] in _HIGH_SEV_TECHNIQUES)
            mitre_factor = min(1.0, 0.3 + 0.2 * len(inp.mitre) + 0.3 * high)
            factors["mitre"] = min(1.0, mitre_factor)
            rationale.append(
                f"{len(inp.mitre)} ATT&CK technique(s); {high} high-severity"
            )
        else:
            factors["mitre"] = 0.0

        factors["asset"] = min(1.0, inp.asset_criticality)
        if inp.asset_criticality >= 0.8:
            rationale.append("High-criticality asset/user affected")

        blast = min(1.0, inp.recipient_count / 100.0)
        factors["email_blast"] = blast
        if inp.recipient_count > 10:
            rationale.append(f"Campaign reached {inp.recipient_count} recipients")

        score = round(sum(_WEIGHTS[k] * v for k, v in factors.items()) * 100, 1)
        return RiskBreakdown(
            score=score,
            severity=_severity_for(score),
            factors={k: round(v, 3) for k, v in factors.items()},
            rationale=rationale or ["No corroborating malicious evidence found"],
        )


_default = RiskScorer()


def score_investigation(inp: RiskInputs) -> RiskBreakdown:
    return _default.score(inp)
