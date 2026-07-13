"""CIRCL hashlookup connector — fully public, **no API key required**.

hashlookup.circl.lu indexes billions of *known* file hashes (NSRL and other
curated sets). Its main value is corroborating that a file is a known-good OS
or vendor binary — which suppresses false positives — and flagging entries that
carry a KnownMalicious tag. Docs: https://hashlookup.circl.lu/
"""
from __future__ import annotations

import httpx

from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.circl_hashlookup")

_ENDPOINT = {
    IOCType.SHA256: "sha256",
    IOCType.SHA1: "sha1",
    IOCType.MD5: "md5",
}


class CIRCLHashlookupConnector(ThreatIntelConnector):
    name = "circl-hashlookup"
    supported_types = frozenset(_ENDPOINT)

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        algo = _ENDPOINT.get(ioc.type)
        if algo is None:
            return None
        url = assert_allowed_url(
            f"https://hashlookup.circl.lu/lookup/{algo}/{ioc.value}")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 404:  # not in any known set — no signal
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN,
                                     score=0.0, detail="hash not in known sets")
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("hashlookup_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)

        known_malicious = data.get("KnownMalicious")
        if known_malicious:
            sources = (", ".join(known_malicious)
                       if isinstance(known_malicious, list) else str(known_malicious))
            return SourceVerdict(
                source=self.name, verdict=Verdict.MALICIOUS, score=0.9,
                detail=f"KnownMalicious: {sources}",
            )

        trust = data.get("hashlookup:trust", 0)
        try:
            trust = int(trust)
        except (TypeError, ValueError):
            trust = 0
        if trust >= 50:
            product = (data.get("ProductName") or data.get("FileName") or
                       "known-good set")
            return SourceVerdict(
                source=self.name, verdict=Verdict.BENIGN, score=0.0,
                detail=f"known-good (trust {trust}): {product}",
            )
        return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0,
                             detail=f"present but low trust ({trust})")
