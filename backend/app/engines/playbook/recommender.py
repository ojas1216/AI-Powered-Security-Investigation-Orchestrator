"""Playbook recommendation engine.

Maps observed MITRE techniques + evidence to containment / eradication / recovery /
detection actions. Every step is `requires_approval=True` — recommendations are never
auto-executed (see SECURITY.md, AI security).
"""
from __future__ import annotations

from app.schemas.common import Verdict
from app.schemas.investigation import MitreTechnique, PlaybookStep

# technique → ordered remediation steps
_RULES: dict[str, list[tuple[str, str, str]]] = {
    "T1071": [
        ("containment", "Block C2 domains/IPs at the egress firewall and proxy",
         "Confirmed command-and-control traffic must be severed first"),
        ("detection", "Add C2 indicators to EDR custom IOC blocklist",
         "Prevent re-beaconing and catch lateral spread"),
    ],
    "T1547": [
        ("eradication", "Remove malicious Run-key persistence on affected hosts",
         "Persistence will survive reboot until removed"),
    ],
    "T1059": [
        ("containment", "Isolate hosts that executed the encoded PowerShell",
         "Live code execution observed; contain before eradication"),
    ],
    "T1486": [
        ("recovery", "Validate backups and prepare restoration runbook",
         "Ransomware impact technique present"),
    ],
    "T1566": [
        ("containment", "Purge the phishing email from all recipient mailboxes",
         "Stop further clicks across the campaign"),
        ("detection", "Tune mail gateway rule for the sender/url pattern",
         "Reduce recurrence of this campaign"),
    ],
}


def recommend_playbook(
    techniques: list[MitreTechnique], overall_verdict: Verdict
) -> list[PlaybookStep]:
    steps: list[PlaybookStep] = []
    seen: set[tuple[str, str]] = set()

    for tech in techniques:
        base = tech.technique_id.split(".")[0]
        for phase, action, rationale in _RULES.get(base, []):
            key = (phase, action)
            if key in seen:
                continue
            seen.add(key)
            steps.append(
                PlaybookStep(phase=phase, action=action, rationale=rationale)
            )

    if overall_verdict is Verdict.MALICIOUS and not steps:
        steps.append(
            PlaybookStep(
                phase="containment",
                action="Escalate to Tier-2/IR for manual containment review",
                rationale="Malicious verdict without a mapped automated playbook",
            )
        )

    # Always close with a detection-engineering improvement.
    steps.append(
        PlaybookStep(
            phase="detection",
            action="Promote confirmed IOCs to the detection ruleset and threat-intel platform",
            rationale="Convert this investigation into durable detection coverage",
        )
    )
    return steps
