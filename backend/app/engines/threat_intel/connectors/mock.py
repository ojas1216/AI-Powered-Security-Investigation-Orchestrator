"""Deterministic mock TI connector.

Lets the whole platform run and be tested offline. The verdict is derived
deterministically from the IOC value so tests are stable, with a small built-in
'known-bad' list to exercise the malicious path.
"""
from __future__ import annotations

import hashlib

from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

_KNOWN_BAD = {
    "evil.com",
    "malware-c2.net",
    "45.155.205.99",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def _deterministic_score(value: str) -> float:
    digest = hashlib.sha256(value.lower().encode()).digest()
    return digest[0] / 255.0


class MockThreatIntelConnector(ThreatIntelConnector):
    name = "mock-ti"
    supported_types = frozenset(IOCType)

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        value = ioc.value.lower()
        if value in _KNOWN_BAD:
            return SourceVerdict(
                source=self.name,
                verdict=Verdict.MALICIOUS,
                score=0.97,
                detail="Matched bundled known-bad list",
            )
        score = _deterministic_score(value)
        if score > 0.85:
            verdict = Verdict.MALICIOUS
        elif score > 0.6:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN
        return SourceVerdict(
            source=self.name, verdict=verdict, score=round(score, 3),
            detail="deterministic mock verdict",
        )
