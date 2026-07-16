"""ThreatFox (abuse.ch) connector — the primary enrichment/testing source.

Offline-first: a bundled cache of representative ThreatFox entries powers
enrichment and regression tests with zero credentials. Online: when
AEGIS_THREATFOX_API_KEY is set it queries the official ThreatFox API
(`search_ioc` with the `Auth-Key` header) and merges results into the cache for
reuse. Failure-isolated — a lookup never raises.

Implements the standard `ThreatIntelConnector.lookup` (so it plugs into the
aggregator) plus a richer `enrich` returning the full ThreatFox record used by
the dossier engine.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.threatfox")

_CACHE_FILE = Path(__file__).parent / "data" / "threatfox_cache.json"
_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

_SUPPORTED = frozenset({
    IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.URL,
    IOCType.SHA256, IOCType.SHA1, IOCType.MD5,
})


class ThreatFoxRecord(BaseModel):
    ioc: str
    ioc_type: str = ""
    threat_type: str = ""
    malware: str = ""
    malware_printable: str = ""
    confidence_level: int = 0
    tags: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    reporter: str = ""
    threat_description: str = ""
    reference: list[str] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)


class ThreatFoxConnector(ThreatIntelConnector):
    name = "threatfox"
    supported_types = _SUPPORTED

    def __init__(self, cache_file: Path = _CACHE_FILE) -> None:
        self._cache: dict[str, dict] = {}
        try:
            self._cache = json.loads(cache_file.read_text(encoding="utf-8")).get(
                "iocs", {})
        except (OSError, ValueError) as exc:  # pragma: no cover - packaging guard
            log.warning("threatfox_cache_load_failed", error=str(exc))

    # -- rich enrichment (dossier) ------------------------------------------

    async def enrich(self, ioc: IOC) -> ThreatFoxRecord | None:
        key = ioc.value.lower()
        rec = self._cache.get(key)
        if rec is None and settings.threatfox_api_key:
            rec = await self._online(ioc)
        if rec is None:
            return None
        return ThreatFoxRecord(ioc=ioc.value, **rec)

    async def _online(self, ioc: IOC) -> dict | None:  # pragma: no cover - network
        import httpx

        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as c:
                resp = await c.post(
                    _API_URL,
                    headers={"Auth-Key": settings.threatfox_api_key},
                    json={"query": "search_ioc", "search_term": ioc.value})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 - never raise from enrichment
            log.warning("threatfox_online_failed", ioc=ioc.key(), error=str(exc))
            return None
        rows = data.get("data") or []
        if not rows:
            return None
        r = rows[0]
        merged = {
            "ioc_type": r.get("ioc_type", ""),
            "threat_type": r.get("threat_type", ""),
            "malware": r.get("malware", ""),
            "malware_printable": r.get("malware_printable", ""),
            "confidence_level": int(r.get("confidence_level", 0) or 0),
            "tags": r.get("tags") or [],
            "first_seen": r.get("first_seen", ""),
            "last_seen": r.get("last_seen", ""),
            "reporter": r.get("reporter", ""),
            "threat_description": r.get("threat_type_desc", ""),
            "reference": [r["reference"]] if r.get("reference") else [],
            "related": [],
        }
        self._cache[ioc.value.lower()] = merged  # cache for offline reuse
        return merged

    # -- standard connector contract ----------------------------------------

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if ioc.type not in _SUPPORTED:
            return None
        rec = await self.enrich(ioc)
        if rec is None:
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
        score = min(1.0, rec.confidence_level / 100.0)
        verdict = (Verdict.MALICIOUS if score >= 0.75
                   else Verdict.SUSPICIOUS if score >= 0.4 else Verdict.UNKNOWN)
        detail = (f"{rec.malware_printable or rec.malware or 'threat'} / "
                  f"{rec.threat_type}") if rec.malware or rec.threat_type else "listed"
        return SourceVerdict(source=self.name, verdict=verdict,
                             score=round(score, 3), detail=detail)


_connector: ThreatFoxConnector | None = None


def build_threatfox_connector() -> ThreatFoxConnector:
    global _connector
    if _connector is None:
        _connector = ThreatFoxConnector()
    return _connector
