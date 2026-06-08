"""Threat-intel correlation: fan out to connectors, fuse verdicts.

Verdict fusion is *weighted and conservative*:
- Each source contributes a malice score in [0,1].
- A small number of high-confidence malicious sources outweighs many low ones
  (we take a weighted blend of the mean and the max, so a single strong
  malicious hit is not drowned out by benign noise).
- Confidence rises with corroboration (number of agreeing sources).

Connectors run concurrently with a bounded semaphore; per-IOC results are cached
(via the injected cache) so a campaign reusing one IOC costs a single upstream call.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import Verdict
from app.schemas.ioc import IOC, EnrichedIOC, SourceVerdict

log = get_logger("ti.aggregator")

_VERDICT_FLOOR = {
    Verdict.MALICIOUS: 0.85,
    Verdict.SUSPICIOUS: 0.5,
    Verdict.BENIGN: 0.0,
    Verdict.UNKNOWN: 0.0,
}


def fuse_verdicts(sources: list[SourceVerdict]) -> tuple[Verdict, float]:
    """Return (verdict, confidence) from per-source verdicts."""
    rated = [s for s in sources if s.verdict is not Verdict.UNKNOWN]
    if not rated:
        return Verdict.UNKNOWN, 0.0

    scores = [s.score for s in rated]
    mean = sum(scores) / len(scores)
    peak = max(scores)
    # 60% weight to the strongest signal, 40% to the consensus (used for confidence).
    fused = 0.6 * peak + 0.4 * mean

    # Verdict tier is peak-dominant: one high-confidence malicious source from a
    # reputable feed is decisive and must not be diluted by benign noise.
    if peak >= _VERDICT_FLOOR[Verdict.MALICIOUS]:
        verdict = Verdict.MALICIOUS
    elif peak >= _VERDICT_FLOOR[Verdict.SUSPICIOUS]:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN

    # Confidence grows with corroboration but never claims certainty.
    agree = sum(1 for s in rated if s.verdict is verdict)
    corroboration = min(1.0, agree / 3.0)
    confidence = round(min(0.99, 0.5 * fused + 0.5 * corroboration), 3)
    return verdict, confidence


class ThreatIntelAggregator:
    def __init__(
        self,
        connectors: list[ThreatIntelConnector],
        max_concurrency: int = 8,
        cache_get: Callable[[str], Awaitable[EnrichedIOC | None]] | None = None,
        cache_set: Callable[[str, EnrichedIOC], Awaitable[None]] | None = None,
    ) -> None:
        self._connectors = connectors
        self._sem = asyncio.Semaphore(max_concurrency)
        self._cache_get = cache_get
        self._cache_set = cache_set

    async def enrich_one(self, ioc: IOC) -> EnrichedIOC:
        if self._cache_get and (cached := await self._cache_get(ioc.key())):
            return cached

        async def run(conn: ThreatIntelConnector) -> SourceVerdict | None:
            if not conn.supports(ioc):
                return None
            async with self._sem:
                try:
                    return await conn.lookup(ioc)
                except Exception as exc:  # connectors shouldn't raise; defend anyway
                    log.warning("connector_raised", connector=conn.name, error=str(exc))
                    return None

        results = await asyncio.gather(*(run(c) for c in self._connectors))
        sources = [r for r in results if r is not None]
        verdict, confidence = fuse_verdicts(sources)
        enriched = EnrichedIOC(
            ioc=ioc,
            verdict=verdict,
            confidence=confidence,
            sources=sources,
            sightings=len(sources),
        )
        if self._cache_set:
            await self._cache_set(ioc.key(), enriched)
        return enriched

    async def enrich_many(self, iocs: list[IOC]) -> list[EnrichedIOC]:
        return list(await asyncio.gather(*(self.enrich_one(i) for i in iocs)))


def build_aggregator() -> ThreatIntelAggregator:
    """Wire connectors based on configured mode.

    In live mode only connectors that actually have a key configured are wired,
    so a deployment with just a VirusTotal key works without erroring on the rest.
    If no key is present at all we fall back to the mock so the platform never
    silently produces empty enrichment.
    """
    if settings.use_mock_connectors:
        from app.engines.threat_intel.connectors.mock import MockThreatIntelConnector

        return ThreatIntelAggregator([MockThreatIntelConnector()])

    from app.engines.threat_intel.connectors.abuseipdb import AbuseIPDBConnector
    from app.engines.threat_intel.connectors.greynoise import GreyNoiseConnector
    from app.engines.threat_intel.connectors.otx import OTXConnector
    from app.engines.threat_intel.connectors.virustotal import VirusTotalConnector

    connectors: list[ThreatIntelConnector] = []
    if settings.virustotal_api_key:
        connectors.append(VirusTotalConnector())
    if settings.abuseipdb_api_key:
        connectors.append(AbuseIPDBConnector())
    if settings.greynoise_api_key:
        connectors.append(GreyNoiseConnector())
    if settings.otx_api_key:
        connectors.append(OTXConnector())

    if not connectors:
        from app.engines.threat_intel.connectors.mock import MockThreatIntelConnector

        log.warning("live_mode_no_keys_configured_fallback_mock")
        connectors.append(MockThreatIntelConnector())

    return ThreatIntelAggregator(connectors)
