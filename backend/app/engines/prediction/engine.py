"""Predictive attack path.

Given the reconstructed kill chain (root cause + observed ATT&CK tactics),
project the attacker's likely next moves along the chain, each with a probability
and a concrete preventative action, plus a short attack simulation. Deterministic
and auditable — a transition model over the ATT&CK tactic ordering, not an LLM
guess. This turns a backward-looking investigation into forward-looking defense.
"""
from __future__ import annotations

from app.schemas.common import Verdict
from app.schemas.investigation import (
    AttackPrediction,
    MitreTechnique,
    PredictedAction,
    RootCause,
)

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
_RANK = {t: i for i, t in enumerate(_TACTIC_ORDER)}

# Per-tactic representative next technique + preventative control.
_PLAYBOOK: dict[str, tuple[str, str, str]] = {
    "persistence": ("T1547", "Boot or Logon Autostart Execution",
                    "Monitor autoruns/scheduled tasks/services; baseline and alert "
                    "on new persistence mechanisms"),
    "privilege-escalation": ("T1548", "Abuse Elevation Control Mechanism",
                             "Enforce least privilege, patch LPE CVEs, alert on UAC bypass"),
    "defense-evasion": ("T1070", "Indicator Removal",
                        "Enable tamper protection and immutable, centralized logging"),
    "credential-access": ("T1003", "OS Credential Dumping",
                          "Enable LSASS/Credential Guard protection and rotate credentials"),
    "discovery": ("T1087", "Account/System Discovery",
                  "Alert on recon tooling and limit directory enumeration"),
    "lateral-movement": ("T1021", "Remote Services",
                         "Segment the network, restrict RDP/SMB, enforce MFA laterally"),
    "collection": ("T1560", "Archive Collected Data",
                   "Apply DLP on staging and alert on mass archive creation"),
    "command-and-control": ("T1071", "Application Layer Protocol",
                            "Block C2 at egress, inspect TLS, enable DNS filtering"),
    "exfiltration": ("T1041", "Exfiltration Over C2 Channel",
                     "Egress DLP, rate-limit outbound, block unsanctioned cloud storage"),
    "impact": ("T1486", "Data Encrypted for Impact",
               "Maintain offline backups, restrict mass file ops, deploy ransomware canaries"),
}
_ENDGAME = {"exfiltration", "impact"}


class PredictionEngine:
    def predict(self, root_cause: RootCause | None,
                mitre: list[MitreTechnique], verdict: Verdict) -> AttackPrediction:
        observed = {t.tactic for t in mitre}
        if root_cause:
            observed |= set(root_cause.kill_chain)
        indices = [_RANK[t] for t in observed if t in _RANK]
        furthest = max(indices) if indices else -1
        current_stage = _TACTIC_ORDER[furthest] if furthest >= 0 else "reconnaissance"

        # Benign/unknown incidents get no forward projection.
        if verdict in (Verdict.BENIGN, Verdict.UNKNOWN):
            return AttackPrediction(
                current_stage=current_stage,
                simulation=["No malicious progression predicted."])

        predictions: list[PredictedAction] = []
        for i in range(furthest + 1, len(_TACTIC_ORDER)):
            tactic = _TACTIC_ORDER[i]
            if tactic not in _PLAYBOOK:
                continue
            distance = i - furthest
            prob = max(0.1, 0.8 * (0.72 ** (distance - 1)))
            if tactic in _ENDGAME:
                prob = min(0.95, prob + 0.1)  # the attacker's objective
            tech_id, name, prevent = _PLAYBOOK[tactic]
            predictions.append(PredictedAction(
                tactic=tactic, technique_id=tech_id, name=name,
                probability=round(prob, 3),
                rationale=f"typical progression after {current_stage}",
                preventative_action=prevent))
            if len(predictions) >= 5:
                break

        simulation = [f"Attacker is currently at '{current_stage}'."]
        simulation += [f"→ {p.tactic}: {p.name} (~{p.probability:.0%})"
                       for p in predictions]
        return AttackPrediction(current_stage=current_stage,
                                predictions=predictions, simulation=simulation)


_engine: PredictionEngine | None = None


def build_prediction_engine() -> PredictionEngine:
    global _engine
    if _engine is None:
        _engine = PredictionEngine()
    return _engine
