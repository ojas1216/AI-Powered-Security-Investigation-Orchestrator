"""SANS ISC / DShield connector — fully public, **no API key required**.

DShield aggregates firewall/honeypot logs from thousands of sensors. For an IP
it reports how many sensor reports exist (`count`), how many distinct targets
were attacked (`attacks`), and whether the IP sits on a curated threat feed.
Docs: https://isc.sans.edu/api/  (please keep the descriptive User-Agent).
"""
from __future__ import annotations

import httpx

from app.core.logging import get_logger
from app.core.ssrf import assert_allowed_url
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.dshield")

_USER_AGENT = "AegisFlow-SOC/1.0 (open-source security research)"

# DShield feeds that describe a host's *function*, not hostility. 8.8.8.8 sits
# on openresolver/myip, so these must never drive a malicious verdict.
_INFORMATIONAL_FEEDS = frozenset({
    "openresolver", "myip", "miner", "torexit", "publicaccess",
})


class DShieldConnector(ThreatIntelConnector):
    name = "dshield"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        url = assert_allowed_url(f"https://isc.sans.edu/api/ip/{ioc.value}?json")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"User-Agent": _USER_AGENT})
            resp.raise_for_status()
            info = resp.json().get("ip") or {}
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("dshield_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)

        count = _as_int(info.get("count"))          # sensor reports
        attacks = _as_int(info.get("attacks"))      # distinct targets
        feeds = info.get("threatfeeds") or {}

        feed_names = set(feeds) if isinstance(feeds, dict) else set()
        hostile_feeds = feed_names - _INFORMATIONAL_FEEDS
        if hostile_feeds:
            return SourceVerdict(
                source=self.name, verdict=Verdict.MALICIOUS, score=0.9,
                detail=f"listed on DShield threat feed(s): "
                       f"{', '.join(sorted(hostile_feeds))}",
            )
        if count >= 500 and attacks >= 25:
            return SourceVerdict(
                source=self.name, verdict=Verdict.MALICIOUS, score=0.85,
                detail=f"{count} sensor reports against {attacks} targets",
            )
        if count > 0:
            score = min(0.65, 0.35 + count / 1000)
            return SourceVerdict(
                source=self.name, verdict=Verdict.SUSPICIOUS, score=round(score, 3),
                detail=f"{count} sensor report(s), {attacks} target(s)",
            )
        return SourceVerdict(
            source=self.name, verdict=Verdict.BENIGN, score=0.05,
            detail="no sensor reports",
        )


def _as_int(value: object) -> int:
    try:
        return int(value)  # DShield returns numbers or numeric strings; null -> 0
    except (TypeError, ValueError):
        return 0
