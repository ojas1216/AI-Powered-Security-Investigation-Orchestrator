"""Threat-intel connector contract.

Every provider implements `lookup` for a single IOC and declares which IOC types
it supports. Connectors must be side-effect free beyond the (SSRF-guarded) HTTP
call and must never raise — they return UNKNOWN on failure so one flaky provider
cannot fail an investigation.
"""
from __future__ import annotations

import abc

from app.schemas.common import IOCType
from app.schemas.ioc import IOC, SourceVerdict


class ThreatIntelConnector(abc.ABC):
    name: str = "base"
    supported_types: frozenset[IOCType] = frozenset()

    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported_types

    @abc.abstractmethod
    async def lookup(self, ioc: IOC) -> SourceVerdict | None:
        """Return this source's verdict for the IOC, or None if not applicable."""
        raise NotImplementedError
