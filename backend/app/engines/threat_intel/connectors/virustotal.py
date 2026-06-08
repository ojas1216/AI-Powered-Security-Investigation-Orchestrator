"""VirusTotal connector (live). Used only when AEGIS_CONNECTOR_MODE=live.

All requests pass the SSRF guard and use a scoped, short-lived API key from Vault.
Never raises: maps any error to UNKNOWN.
"""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.virustotal")

_PATH = {
    IOCType.SHA256: "files",
    IOCType.SHA1: "files",
    IOCType.MD5: "files",
    IOCType.DOMAIN: "domains",
    IOCType.IPV4: "ip_addresses",
    IOCType.URL: "urls",
}


class VirusTotalConnector(ThreatIntelConnector):
    name = "virustotal"
    supported_types = frozenset(_PATH)

    def __init__(self, api_key: str | None = None) -> None:
        self._key = api_key or settings.virustotal_api_key

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._key or ioc.type not in _PATH:
            return None
        url = assert_allowed_url(
            f"https://www.virustotal.com/api/v3/{_PATH[ioc.type]}/{ioc.value}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"x-apikey": self._key})
            if resp.status_code == 404:
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
            resp.raise_for_status()
            stats = (
                resp.json().get("data", {}).get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = (malicious + 0.5 * suspicious) / total
            verdict = (
                Verdict.MALICIOUS if malicious >= 3
                else Verdict.SUSPICIOUS if malicious or suspicious
                else Verdict.BENIGN
            )
            return SourceVerdict(
                source=self.name, verdict=verdict, score=round(min(score, 1.0), 3),
                detail=f"{malicious} malicious / {total} engines",
            )
        except httpx.HTTPError as exc:
            log.warning("vt_lookup_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
