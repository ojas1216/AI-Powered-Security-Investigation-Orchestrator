"""AbuseIPDB connector (live). IP reputation only."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.abuseipdb")


class AbuseIPDBConnector(ThreatIntelConnector):
    name = "abuseipdb"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})

    def __init__(self, api_key: str | None = None) -> None:
        self._key = api_key or settings.abuseipdb_api_key

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._key:
            return None
        url = assert_allowed_url("https://api.abuseipdb.com/api/v2/check")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    url,
                    headers={"Key": self._key, "Accept": "application/json"},
                    params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            confidence = data.get("abuseConfidenceScore", 0) / 100.0
            verdict = (
                Verdict.MALICIOUS if confidence >= 0.75
                else Verdict.SUSPICIOUS if confidence >= 0.25
                else Verdict.BENIGN
            )
            return SourceVerdict(
                source=self.name, verdict=verdict, score=round(confidence, 3),
                detail=f"abuse confidence {data.get('abuseConfidenceScore', 0)}%, "
                f"reports={data.get('totalReports', 0)}",
            )
        except httpx.HTTPError as exc:
            log.warning("abuseipdb_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
