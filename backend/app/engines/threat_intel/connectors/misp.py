"""MISP connector (live).

Operator-hosted; base URL from trusted config (same SSRF reasoning as OpenCTI —
not routed through the public allow-list, IOC value sent only in the JSON body).

Verdict heuristic: query attributes by value via /attributes/restSearch. Any
to_ids=true attribute is a strong malicious signal (the owning org flagged it for
detection); otherwise sightings/attribute presence yields suspicious.
"""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.misp")


class MISPConnector(ThreatIntelConnector):
    name = "misp"
    supported_types = frozenset(
        {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
         IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.EMAIL}
    )

    def __init__(self, url: str | None = None, key: str | None = None) -> None:
        self._url = (url or settings.misp_url).rstrip("/")
        self._key = key or settings.misp_key

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._url or not self._key:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=12.0, verify=settings.internal_tls_verify
            ) as client:
                resp = await client.post(
                    f"{self._url}/attributes/restSearch",
                    headers={
                        "Authorization": self._key,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={"value": ioc.value, "limit": 25, "returnFormat": "json"},
                )
            resp.raise_for_status()
            attrs = resp.json().get("response", {}).get("Attribute", [])
            if not attrs:
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0,
                                     detail="no attributes in MISP")
            to_ids = sum(1 for a in attrs if a.get("to_ids") in (True, "1", 1))
            if to_ids:
                verdict, score = Verdict.MALICIOUS, min(1.0, 0.7 + 0.05 * to_ids)
            else:
                verdict, score = Verdict.SUSPICIOUS, 0.5
            return SourceVerdict(
                source=self.name, verdict=verdict, score=round(score, 3),
                detail=f"{len(attrs)} attribute(s), {to_ids} flagged to_ids",
            )
        except httpx.HTTPError as exc:
            log.warning("misp_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
