"""EDR hunting contract (CrowdStrike / SentinelOne / Defender / Wazuh)."""
from __future__ import annotations

import abc
from datetime import datetime

from pydantic import BaseModel

from app.schemas.ioc import IOC


class EDRHit(BaseModel):
    ioc: IOC
    host: str
    user: str | None = None
    process: str | None = None
    observed_at: datetime
    detail: str = ""


class EDRConnector(abc.ABC):
    name = "base-edr"

    @abc.abstractmethod
    async def hunt(self, iocs: list[IOC]) -> list[EDRHit]:
        """Search telemetry for any of the IOCs; return confirmed hits."""
        raise NotImplementedError
