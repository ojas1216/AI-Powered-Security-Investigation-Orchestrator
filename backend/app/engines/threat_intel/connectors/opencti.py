"""OpenCTI connector (live).

OpenCTI is operator-hosted; the base URL comes from trusted configuration, not from
attacker input, and is commonly on a private network. We therefore do NOT route it
through the public-egress SSRF allow-list (which blocks RFC1918). The untrusted IOC
value is passed only as a parameterized GraphQL variable, never concatenated into the
URL/host, so there is no SSRF or query-injection surface.

The verdict is derived from OpenCTI's x_opencti_score (0-100) for the matched object.
The exact GraphQL shape varies slightly by OpenCTI version; parsing is defensive.
"""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.threat_intel.base import ThreatIntelConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.opencti")

_SEARCH_QUERY = """
query SearchObservable($search: String!) {
  stixCoreObjects(search: $search, first: 1) {
    edges {
      node {
        ... on StixCyberObservable { x_opencti_score }
        ... on Indicator { x_opencti_score confidence }
      }
    }
  }
}
"""


def _extract_score(payload: dict) -> int | None:
    edges = (
        payload.get("data", {}).get("stixCoreObjects", {}).get("edges", [])
    )
    for edge in edges:
        node = edge.get("node", {})
        score = node.get("x_opencti_score")
        if isinstance(score, int):
            return score
    return None


class OpenCTIConnector(ThreatIntelConnector):
    name = "opencti"
    supported_types = frozenset(
        {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
         IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.EMAIL}
    )

    def __init__(self, url: str | None = None, token: str | None = None) -> None:
        self._url = (url or settings.opencti_url).rstrip("/")
        self._token = token or settings.opencti_token

    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if not self._url or not self._token:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=12.0, verify=settings.internal_tls_verify
            ) as client:
                resp = await client.post(
                    f"{self._url}/graphql",
                    headers={"Authorization": f"Bearer {self._token}"},
                    json={"query": _SEARCH_QUERY, "variables": {"search": ioc.value}},
                )
            resp.raise_for_status()
            score = _extract_score(resp.json())
            if score is None:
                return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0,
                                     detail="no matching object in OpenCTI")
            norm = score / 100.0
            verdict = (
                Verdict.MALICIOUS if score >= 75
                else Verdict.SUSPICIOUS if score >= 40
                else Verdict.BENIGN
            )
            return SourceVerdict(source=self.name, verdict=verdict, score=round(norm, 3),
                                 detail=f"x_opencti_score={score}")
        except httpx.HTTPError as exc:
            log.warning("opencti_failed", ioc=ioc.key(), error=str(exc))
            return SourceVerdict(source=self.name, verdict=Verdict.UNKNOWN, score=0.0)
