"""Additional dossier connectors + circuit breaker."""
from __future__ import annotations

import pytest

from app.engines.threat_intel.circuit import CircuitBreaker
from app.engines.threat_intel.dossier_sources import (
    MalwareBazaarConnector,
    SpamhausConnector,
    TalosConnector,
    URLHausConnector,
    build_dossier_connectors,
)
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC

_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------- circuit breaker


def test_circuit_opens_and_half_opens():
    clock = {"t": 0.0}
    cb = CircuitBreaker(threshold=2, cooldown_seconds=30, now_fn=lambda: clock["t"])
    assert cb.available()
    cb.record_failure()
    cb.record_failure()
    assert not cb.available()          # open after 2 failures
    clock["t"] = 31
    assert cb.available()              # half-open after cooldown
    cb.record_success()
    assert cb.available()


# ---------------------------------------------------------------- connectors


@pytest.mark.asyncio
async def test_urlhaus_hit_and_miss():
    c = URLHausConnector()
    hit = await c.enrich(IOC(type=IOCType.DOMAIN, value="malware-c2.net"))
    assert hit and hit.verdict is Verdict.MALICIOUS and hit.malware_family == "QakBot"
    assert await c.enrich(IOC(type=IOCType.DOMAIN, value="clean.example")) is None
    assert await c.enrich(IOC(type=IOCType.IPV4, value="1.2.3.4")) is None  # unsupported


@pytest.mark.asyncio
async def test_malwarebazaar_hash():
    c = MalwareBazaarConnector()
    hit = await c.enrich(IOC(type=IOCType.SHA256, value=_SHA))
    assert hit and hit.malware_family == "QakBot" and hit.references


@pytest.mark.asyncio
async def test_spamhaus_listing():
    hit = await SpamhausConnector().enrich(
        IOC(type=IOCType.IPV4, value="45.155.205.99"))
    assert hit and hit.verdict is Verdict.MALICIOUS
    assert "sbl" in hit.tags


@pytest.mark.asyncio
async def test_talos_reputation_poor_and_favorable():
    poor = await TalosConnector().enrich(IOC(type=IOCType.IPV4, value="45.155.205.99"))
    good = await TalosConnector().enrich(IOC(type=IOCType.IPV4, value="8.8.8.8"))
    assert poor.verdict is Verdict.MALICIOUS
    assert good.verdict is Verdict.BENIGN


@pytest.mark.asyncio
async def test_connectors_never_raise_on_unsupported():
    for c in build_dossier_connectors():
        # a mutex is unsupported by all of them -> None, no exception
        assert await c.enrich(IOC(type=IOCType.MUTEX, value="Global\\x")) is None


# ---------------------------------------------------------------- dossier integration


@pytest.mark.asyncio
async def test_dossier_aggregates_multiple_sources():
    from app.engines.threat_intel import dossier as dm

    dm._engine = None
    d = await dm.build_dossier_engine().build("malware-c2.net", "sources-t")
    sources = {p.source for p in d.threat_intel}
    assert {"threatfox", "urlhaus", "spamhaus", "talos"} <= sources
    assert d.verdict is Verdict.MALICIOUS
    assert d.risk_score > 90  # corroboration across many sources
    assert "QakBot" in d.relationships.threat_actors
