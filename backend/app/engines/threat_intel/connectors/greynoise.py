"""GreyNoise connector (live). Distinguishes targeted vs. internet-background noise."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.greynoise")


class GreyNoiseConnector(ThreatIntelConnector):
    name = "greynoise"
    supported_types = frozenset({IOCType.IPV4})

    def __init__(self, api_key: str | None = None) -> None:
        self._key = api_key or settings.greynoise_api_key

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._key:
            return None
        url = assert_allowed_url(
            f"https://api.greynoise.io/v3/community/{ioc.value}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"key": self._key})
            if resp.status_code == 404:
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0,
                                     detail="not observed by GreyNoise")
            resp.raise_for_status()
            data = resp.json()
            classification = data.get("classification", "unknown")
            mapping = {
                "malicious": (Verdict.MALICIOUS, 0.9),
                "suspicious": (Verdict.SUSPICIOUS, 0.6),
                "benign": (Verdict.BENIGN, 0.05),
            }
            verdict, score = mapping.get(classification, (Verdict.UNKNOWN, 0.0))
            return SourceVerdict(
                source=self.name, verdict=verdict, score=score,
                detail=f"classification={classification}, noise={data.get('noise')}",
            )
        except httpx.HTTPError as exc:
            log.warning("greynoise_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
