"""Lightweight ATT&CK mapper.

Heuristic tagging from observed artifacts/behaviors. In production this is backed
by the full ATT&CK STIX bundle + sandbox-reported signatures; here we map a curated
set of common behaviors so the pipeline produces real, explainable technique tags.
"""
from __future__ import annotations

from app.schemas.investigation import MitreTechnique

_TECHNIQUES = {
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access"),
    "T1204.001": ("User Execution: Malicious Link", "execution"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1071.001": ("Application Layer Protocol: Web Protocols (C2)", "command-and-control"),
    "T1486": ("Data Encrypted for Impact", "impact"),
}

# keyword → technique id
_SIGNALS = {
    "powershell": "T1059.001",
    "powershell.exe": "T1059.001",
    "-enc": "T1059.001",
    "http": "T1071.001",
    "run key": "T1547.001",
    "currentversion\\run": "T1547.001",
    "encrypt": "T1486",
    ".lnk": "T1204.002",
    "clicked": "T1204.001",
    "url": "T1566.002",
}


def map_techniques(signals: list[str], has_malicious_url: bool = False) -> list[MitreTechnique]:
    found: dict[str, MitreTechnique] = {}

    def add(tid: str) -> None:
        if tid in _TECHNIQUES and tid not in found:
            name, tactic = _TECHNIQUES[tid]
            found[tid] = MitreTechnique(technique_id=tid, name=name, tactic=tactic)

    if has_malicious_url:
        add("T1566.002")
        add("T1204.001")

    lowered = " ".join(s.lower() for s in signals)
    for keyword, tid in _SIGNALS.items():
        if keyword in lowered:
            add(tid)

    return list(found.values())
