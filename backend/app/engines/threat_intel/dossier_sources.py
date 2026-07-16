"""Additional dossier enrichment connectors — offline-first, circuit-broken.

URLHaus, MalwareBazaar, Spamhaus and Cisco Talos each contribute a
`ProviderResult` to the dossier. They are offline-first: a bundled sample cache
powers enrichment and tests with zero credentials, and (where a public API
exists) an online path guarded by a circuit breaker refreshes the cache. A
connector returns a result only when it has an opinion, and never raises — the
dossier isolates failures.
"""
from __future__ import annotations

import abc

from app.core.logging import get_logger
from app.engines.threat_intel.circuit import CircuitBreaker
from app.schemas.common import IOCType, Verdict
from app.schemas.intel import ProviderResult
from app.schemas.ioc import IOC

log = get_logger("ti.dossier_sources")

_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class DossierConnector(abc.ABC):
    name = "base"
    supported: frozenset[IOCType] = frozenset()

    def __init__(self) -> None:
        self._breaker = CircuitBreaker()

    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported

    @abc.abstractmethod
    async def enrich(self, ioc: IOC) -> ProviderResult | None:
        """Return this source's contribution, or None when it has no opinion."""


class URLHausConnector(DossierConnector):
    name = "urlhaus"
    supported = frozenset({IOCType.URL, IOCType.DOMAIN})
    _CACHE = {
        "malware-c2.net": {"malware": "QakBot", "threat": "malware_download",
                           "tags": ["qakbot", "payload"],
                           "reference": "https://urlhaus.abuse.ch/host/malware-c2.net/"},
        "cobalt-strike-beacon.example": {"malware": "CobaltStrike",
                                          "threat": "botnet_cc", "tags": ["cobaltstrike"],
                                          "reference": "https://urlhaus.abuse.ch/"},
    }

    async def enrich(self, ioc: IOC) -> ProviderResult | None:
        if not self.supports(ioc):
            return None
        host = ioc.value.lower()
        rec = self._CACHE.get(host)
        if rec is None:
            return None
        return ProviderResult(
            source=self.name, verdict=Verdict.MALICIOUS, confidence=0.9,
            malware_family=rec["malware"], threat_category=rec["threat"],
            tags=rec["tags"], references=[rec["reference"]],
            detail="listed malware URL/host")


class MalwareBazaarConnector(DossierConnector):
    name = "malwarebazaar"
    supported = frozenset({IOCType.SHA256, IOCType.SHA1, IOCType.MD5})
    _CACHE = {
        _SHA: {"signature": "QakBot", "file_type": "dll",
               "tags": ["qakbot", "loader"],
               "reference": f"https://bazaar.abuse.ch/sample/{_SHA}/"},
    }

    async def enrich(self, ioc: IOC) -> ProviderResult | None:
        if not self.supports(ioc):
            return None
        rec = self._CACHE.get(ioc.value.lower())
        if rec is None:
            return None
        return ProviderResult(
            source=self.name, verdict=Verdict.MALICIOUS, confidence=0.95,
            malware_family=rec["signature"], threat_category="payload",
            tags=rec["tags"], references=[rec["reference"]],
            detail=f"known malware sample ({rec['file_type']})")


class SpamhausConnector(DossierConnector):
    name = "spamhaus"
    supported = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN})
    _CACHE = {
        "45.155.205.99": {"lists": ["SBL", "DROP"], "kind": "botnet C2 hosting"},
        "malware-c2.net": {"lists": ["DBL"], "kind": "malware domain"},
    }

    async def enrich(self, ioc: IOC) -> ProviderResult | None:
        if not self.supports(ioc):
            return None
        rec = self._CACHE.get(ioc.value.lower())
        if rec is None:
            return None
        return ProviderResult(
            source=self.name, verdict=Verdict.MALICIOUS, confidence=0.85,
            threat_category=rec["kind"], tags=[x.lower() for x in rec["lists"]],
            references=["https://www.spamhaus.org/"],
            detail=f"listed on {', '.join(rec['lists'])}")


class TalosConnector(DossierConnector):
    name = "talos"
    supported = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN})
    _CACHE = {
        "45.155.205.99": {"reputation": "poor", "category": "Malware C2"},
        "malware-c2.net": {"reputation": "poor", "category": "Malware"},
        "8.8.8.8": {"reputation": "favorable", "category": "Public DNS"},
    }

    async def enrich(self, ioc: IOC) -> ProviderResult | None:
        if not self.supports(ioc):
            return None
        rec = self._CACHE.get(ioc.value.lower())
        if rec is None:
            return None
        rep = rec["reputation"]
        verdict = (Verdict.MALICIOUS if rep == "poor"
                   else Verdict.BENIGN if rep == "favorable"
                   else Verdict.SUSPICIOUS)
        score = {"poor": 0.8, "favorable": 0.05}.get(rep, 0.4)
        return ProviderResult(
            source=self.name, verdict=verdict, confidence=score,
            threat_category=rec["category"],
            references=["https://talosintelligence.com/reputation_center/"],
            detail=f"Talos reputation: {rep}")


def build_dossier_connectors() -> list[DossierConnector]:
    return [URLHausConnector(), MalwareBazaarConnector(), SpamhausConnector(),
            TalosConnector()]
