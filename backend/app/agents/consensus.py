"""Consensus + confidence engine.

The final verdict is never a single agent's call. Independent evidence sources —
threat intel, EDR (on-host), sandbox, detection rules, ATT&CK — each cast a
weighted vote. The engine fuses them into a verdict with an explainable
confidence, ranked alternative hypotheses, and the supporting / rejected
observations behind the decision (satisfies the Explainable-AI contract in
docs — no black-box conclusions).

Design: deterministic and auditable. A source only votes when it has evidence
(it abstains otherwise), so a conclusion resting on a single weak voter is
inherently low-confidence — that is how "reject unsupported conclusions" falls
out of the math rather than a special case.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.schemas.common import Verdict
from app.schemas.investigation import (
    ConsensusResult,
    ConsensusVote,
    DetectionMatch,
    Hypothesis,
    MitreTechnique,
)
from app.schemas.ioc import EnrichedIOC

# Source reliability weights. EDR (observed on-host activity) is the strongest
# single signal; ATT&CK presence is the weakest (behavioral, not confirmatory).
_WEIGHTS = {
    "edr": 0.30,
    "threat_intel": 0.25,
    "sandbox": 0.20,
    "detections": 0.15,
    "mitre": 0.10,
}
_SEVERITY_MALICE = {"critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.3,
                    "info": 0.15}
_HIGH_SEV_TACTICS = {"impact", "credential-access", "command-and-control",
                     "exfiltration", "lateral-movement"}


@dataclass
class _Voter:
    name: str
    verdict: Verdict
    malice: float
    confidence: float
    rationale: str


def _verdict_for(malice: float) -> Verdict:
    if malice >= 0.70:
        return Verdict.MALICIOUS
    if malice >= 0.40:
        return Verdict.SUSPICIOUS
    if malice >= 0.15:
        return Verdict.BENIGN
    return Verdict.BENIGN


class ConsensusEngine:
    def decide(self, *, iocs: list[EnrichedIOC], edr_hit_count: int,
               sandbox_malscore: float, detections: list[DetectionMatch],
               mitre: list[MitreTechnique]) -> ConsensusResult:
        voters = self._collect_voters(iocs, edr_hit_count, sandbox_malscore,
                                      detections, mitre)
        if not voters:
            return ConsensusResult(
                verdict=Verdict.UNKNOWN, confidence=0.0, agreement=0.0,
                reasoning=["No evidence source produced a signal; verdict unknown."])

        total_w = sum(_WEIGHTS[v.name] for v in voters)
        weighted_malice = sum(_WEIGHTS[v.name] * v.malice for v in voters) / total_w
        verdict = _verdict_for(weighted_malice)

        agreement = sum(_WEIGHTS[v.name] for v in voters
                        if v.verdict is verdict) / total_w
        participation = len(voters) / len(_WEIGHTS)
        decisiveness = abs(weighted_malice - 0.4) / 0.6  # distance from the boundary
        confidence = 0.4 * agreement + 0.3 * participation + 0.3 * min(1.0, decisiveness)
        # A lone voter can never yield a confident final decision.
        if len(voters) == 1:
            confidence *= 0.6
        confidence = round(min(1.0, confidence), 3)

        votes = [
            ConsensusVote(voter=v.name, verdict=v.verdict, malice=round(v.malice, 3),
                          weight=_WEIGHTS[v.name], confidence=round(v.confidence, 3),
                          rationale=v.rationale)
            for v in voters
        ]
        supporting = [f"{v.name}: {v.rationale}" for v in voters
                      if v.verdict is verdict]
        rejected = [f"{v.name}: {v.rationale}" for v in voters
                    if v.verdict is not verdict]
        if len(voters) == 1:
            rejected.append("Only one evidence source voted; confidence reduced "
                            "(no single source decides alone).")

        return ConsensusResult(
            verdict=verdict, confidence=confidence, agreement=round(agreement, 3),
            votes=votes,
            hypotheses=self._hypotheses(voters, total_w, verdict),
            supporting=supporting, rejected=rejected,
            reasoning=self._reasoning(voters, weighted_malice, verdict, confidence,
                                      agreement))

    # ------------------------------------------------------------- voters

    def _collect_voters(self, iocs, edr_hit_count, sandbox_malscore, detections,
                        mitre) -> list[_Voter]:
        voters: list[_Voter] = []

        rated = [e for e in iocs if e.verdict is not Verdict.UNKNOWN]
        if rated:
            mal = [e for e in rated if e.verdict is Verdict.MALICIOUS]
            if mal:
                top = max(mal, key=lambda e: e.confidence)
                # Malice = strongest malicious *source* score (how malicious the
                # feeds say it is); confidence = fused corroboration certainty.
                malice = max(
                    (s.score for e in mal for s in e.sources
                     if s.verdict is Verdict.MALICIOUS),
                    default=top.confidence)
                voters.append(_Voter(
                    "threat_intel", Verdict.MALICIOUS, min(1.0, malice),
                    top.confidence,
                    f"{len(mal)} malicious IOC(s); strongest {top.ioc.value} "
                    f"(conf {top.confidence:.2f})"))
            else:
                sus = [e for e in rated if e.verdict is Verdict.SUSPICIOUS]
                if sus:
                    voters.append(_Voter("threat_intel", Verdict.SUSPICIOUS, 0.5,
                                         0.5, f"{len(sus)} suspicious IOC(s)"))
                else:
                    voters.append(_Voter("threat_intel", Verdict.BENIGN, 0.1, 0.6,
                                         "all rated IOCs benign"))

        if edr_hit_count > 0:
            voters.append(_Voter(
                "edr", Verdict.MALICIOUS, 0.9, 0.9,
                f"{edr_hit_count} on-host sighting(s) confirm activity"))

        if sandbox_malscore > 0:
            voters.append(_Voter(
                "sandbox", _verdict_for(sandbox_malscore), sandbox_malscore,
                0.8, f"detonation malscore {sandbox_malscore:.2f}"))

        if detections:
            worst = min(detections, key=lambda d: _sev_rank(d.severity.value))
            malice = _SEVERITY_MALICE.get(worst.severity.value, 0.5)
            voters.append(_Voter(
                "detections", _verdict_for(malice), malice, 0.7,
                f"{len(detections)} rule(s) fired; worst {worst.rule_id} "
                f"({worst.severity.value})"))

        if mitre:
            high = [t for t in mitre if t.tactic in _HIGH_SEV_TACTICS]
            malice = min(0.8, 0.3 + 0.12 * len(high))
            voters.append(_Voter(
                "mitre", _verdict_for(malice), malice, 0.5,
                f"{len(mitre)} technique(s), {len(high)} high-severity tactic(s)"))

        return voters

    # ------------------------------------------------------------- explainability

    def _hypotheses(self, voters, total_w, chosen) -> list[Hypothesis]:
        buckets: dict[Verdict, float] = {}
        for v in voters:
            buckets[v.verdict] = buckets.get(v.verdict, 0.0) + _WEIGHTS[v.name]
        rationale = {
            Verdict.MALICIOUS: "corroborated malicious evidence",
            Verdict.SUSPICIOUS: "ambiguous / partial signals",
            Verdict.BENIGN: "no malicious corroboration",
            Verdict.UNKNOWN: "insufficient evidence",
        }
        out = [
            Hypothesis(verdict=vd, probability=round(w / total_w, 3),
                       rationale=rationale.get(vd, ""))
            for vd, w in sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)
        ]
        # Ensure the chosen verdict appears (it may differ from the top bucket
        # when scores, not vote counts, cross a threshold).
        if not any(h.verdict is chosen for h in out):
            out.insert(0, Hypothesis(verdict=chosen, probability=0.0,
                                     rationale="score-weighted fusion"))
        return out

    def _reasoning(self, voters, weighted_malice, verdict, confidence,
                   agreement) -> list[str]:
        chain = [
            f"{len(voters)} independent evidence source(s) voted "
            f"({', '.join(v.name for v in voters)}).",
        ]
        chain += [f"{v.name} → {v.verdict.value} (malice {v.malice:.2f}): "
                  f"{v.rationale}" for v in voters]
        chain.append(
            f"Weighted malice {weighted_malice:.2f} → verdict {verdict.value.upper()} "
            f"at {confidence:.0%} confidence (inter-source agreement {agreement:.0%}).")
        return chain


def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


_engine: ConsensusEngine | None = None


def build_consensus_engine() -> ConsensusEngine:
    global _engine
    if _engine is None:
        _engine = ConsensusEngine()
    return _engine
