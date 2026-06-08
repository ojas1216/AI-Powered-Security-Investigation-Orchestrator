"""Mock EDR: returns deterministic 'confirmed' hits for known-bad IOCs so the
risk engine and affected-host logic have realistic input offline."""
from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.engines.edr.base import EDRConnector, EDRHit
from app.schemas.common import Verdict
from app.schemas.ioc import IOC

_CONFIRMED_VALUES = {
    "malware-c2.net",
    "45.155.205.99",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


class MockEDR(EDRConnector):
    name = "mock-edr"

    async def hunt(self, iocs: list[IOC]) -> list[EDRHit]:
        hits: list[EDRHit] = []
        for i, ioc in enumerate(iocs):
            if ioc.value.lower() in _CONFIRMED_VALUES:
                hits.append(
                    EDRHit(
                        ioc=ioc,
                        host=f"WS-FIN-{42 + i:03d}",
                        user="jdoe",
                        process="powershell.exe",
                        observed_at=datetime.now(timezone.utc),
                        detail=f"IOC {ioc.value} observed in process execution",
                    )
                )
        return hits


def build_edr() -> EDRConnector:
    if settings.use_mock_connectors:
        return MockEDR()
    return MockEDR()
