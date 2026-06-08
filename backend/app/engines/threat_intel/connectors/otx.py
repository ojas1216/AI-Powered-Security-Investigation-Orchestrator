"""AlienVault OTX connector (live). Pulse count drives the verdict."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.otx")

_SECTION = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.SHA256: "file",
    IOCType.SHA1: "file",
    IOCType.MD5: "file",
}


class OTXConnector(ThreatIntelConnector):
    name = "otx"
    supported_types = frozenset(_SECTION)

    def __init__(self, api_key: str | None = None) -> None:
        self._key = api_key or settings.otx_api_key

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._key or ioc.type not in _SECTION:
            return None
        section = _SECTION[ioc.type]
        url = assert_allowed_url(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc.value}/general"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"X-OTX-API-KEY": self._key})
            if resp.status_code == 404:
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
            resp.raise_for_status()
            pulses = resp.json().get("pulse_info", {}).get("count", 0)
            # Many pulses → high confidence malicious; a few → suspicious.
            if pulses >= 5:
                verdict, score = Verdict.MALICIOUS, min(1.0, 0.6 + pulses / 50)
            elif pulses >= 1:
                verdict, score = Verdict.SUSPICIOUS, 0.5
            else:
                verdict, score = Verdict.BENIGN, 0.05
            return SourceVerdict(
                source=self.name, verdict=verdict, score=round(score, 3),
                detail=f"{pulses} OTX pulse(s)",
            )
        except httpx.HTTPError as exc:
            log.warning("otx_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
