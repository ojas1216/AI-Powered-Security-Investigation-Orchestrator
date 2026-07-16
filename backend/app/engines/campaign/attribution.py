"""Threat-actor *type* attribution — deterministic, confidence-scored.

Estimates the KIND of adversary (APT / crimeware / ransomware / insider /
hacktivist / botnet) from the incident's TTP, infrastructure and malware profile.
It never names a specific group (that would be fabrication) and returns
`unattributed` with low confidence when the evidence is not distinctive.

Rule-based and auditable: like the planner and consensus, attribution must be
explainable, so it reports the exact signals behind the estimate.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.schemas.investigation import Attribution

# ATT&CK technique-id prefixes that characterize each actor type.
_RANSOMWARE_TECHS = {"T1486", "T1490", "T1489", "T1491"}
_CRED_ACCESS = {"T1003", "T1110", "T1555", "T1552", "T1558"}
_LATERAL = {"T1021", "T1570", "T1210", "T1534"}
_C2 = {"T1071", "T1105", "T1572", "T1090"}
_PHISHING = {"T1566"}
_VALID_ACCOUNTS = {"T1078"}
_HIGH_VALUE_TACTICS = {"initial-access", "execution", "persistence",
                       "privilege-escalation", "defense-evasion",
                       "credential-access", "lateral-movement",
                       "command-and-control", "exfiltration"}


@dataclass
class _Candidate:
    actor_type: str
    confidence: float
    rationale: str
    signals: list[str]


def _prefix_hits(techniques: set[str], group: set[str]) -> list[str]:
    """Technique ids in `techniques` whose base id is in `group`."""
    return sorted(t for t in techniques if t.split(".")[0] in group)


class AttributionEngine:
    def attribute(self, *, techniques: set[str], tactics: set[str],
                  infra_count: int, malware_count: int, identity_count: int,
                  host_count: int) -> Attribution:
        candidates: list[_Candidate] = []

        ransom = _prefix_hits(techniques, _RANSOMWARE_TECHS)
        if ransom:
            candidates.append(_Candidate(
                "ransomware", 0.85,
                "impact techniques consistent with ransomware staging/execution",
                ransom))

        valid = _prefix_hits(techniques, _VALID_ACCOUNTS)
        if valid and infra_count == 0 and malware_count == 0:
            candidates.append(_Candidate(
                "insider", 0.6,
                "valid-account use with no external infrastructure or malware",
                valid))

        c2 = _prefix_hits(techniques, _C2)
        if c2 and infra_count >= 3 and host_count >= 3:
            candidates.append(_Candidate(
                "botnet", 0.65,
                "C2 protocols over many hosts and infrastructure nodes",
                c2))

        cred = _prefix_hits(techniques, _CRED_ACCESS)
        lateral = _prefix_hits(techniques, _LATERAL)
        breadth = len(tactics & _HIGH_VALUE_TACTICS)
        if breadth >= 4 and (cred or lateral):
            conf = min(0.8, 0.45 + 0.08 * breadth)
            candidates.append(_Candidate(
                "apt", conf,
                f"multi-stage kill chain ({breadth} tactics) with "
                f"{'credential access' if cred else 'lateral movement'}",
                sorted(set(cred) | set(lateral))))

        phish = _prefix_hits(techniques, _PHISHING)
        if phish and malware_count >= 1:
            candidates.append(_Candidate(
                "crimeware", 0.6,
                "phishing delivery paired with commodity malware",
                phish))

        if not candidates:
            return Attribution(
                actor_type="unattributed", confidence=0.0,
                rationale=["No distinctive actor-type signature in the observed "
                           "TTPs; attribution withheld."], signals=[])

        best = max(candidates, key=lambda c: c.confidence)
        others = [c for c in candidates if c is not best]
        rationale = [best.rationale]
        if others:
            rationale.append("alternatives considered: "
                             + ", ".join(f"{c.actor_type} ({c.confidence:.0%})"
                                         for c in others))
        return Attribution(
            actor_type=best.actor_type, confidence=round(best.confidence, 3),
            rationale=rationale, signals=best.signals)


_engine: AttributionEngine | None = None


def build_attribution_engine() -> AttributionEngine:
    global _engine
    if _engine is None:
        _engine = AttributionEngine()
    return _engine
