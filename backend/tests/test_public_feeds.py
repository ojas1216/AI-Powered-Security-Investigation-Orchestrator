"""Keyless public TI connectors (DShield, CIRCL hashlookup) — free, no API key."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.engines.threat_intel.connectors.circl_hashlookup import (
    CIRCLHashlookupConnector,
)
from app.engines.threat_intel.connectors.dshield import DShieldConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------- DShield


@pytest.mark.asyncio
@respx.mock
async def test_dshield_threatfeed_listing_is_malicious():
    respx.get("https://isc.sans.edu/api/ip/45.155.205.99?json").mock(
        return_value=httpx.Response(200, json={
            "ip": {"number": "45.155.205.99", "count": 4200, "attacks": 90,
                   "threatfeeds": {"blocklistde22": {"lastseen": "2026-07-12"}}},
        }))
    v = await DShieldConnector().lookup(IOC(type=IOCType.IPV4, value="45.155.205.99"))
    assert v is not None and v.verdict is Verdict.MALICIOUS
    assert v.score >= 0.85 and "blocklistde22" in (v.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_dshield_scanner_activity_is_suspicious():
    respx.get("https://isc.sans.edu/api/ip/203.0.113.7?json").mock(
        return_value=httpx.Response(200, json={
            "ip": {"count": "42", "attacks": "3", "threatfeeds": None},
        }))
    v = await DShieldConnector().lookup(IOC(type=IOCType.IPV4, value="203.0.113.7"))
    assert v is not None and v.verdict is Verdict.SUSPICIOUS
    assert "42 sensor report(s)" in (v.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_dshield_informational_feeds_never_flag_malicious():
    """8.8.8.8 sits on openresolver/myip — function descriptors, not hostility."""
    respx.get("https://isc.sans.edu/api/ip/8.8.8.8?json").mock(
        return_value=httpx.Response(200, json={
            "ip": {"count": 0, "attacks": 0,
                   "threatfeeds": {"openresolver": {}, "myip": {}}},
        }))
    v = await DShieldConnector().lookup(IOC(type=IOCType.IPV4, value="8.8.8.8"))
    assert v is not None and v.verdict is Verdict.BENIGN


@pytest.mark.asyncio
@respx.mock
async def test_dshield_clean_ip_is_benign_and_errors_are_unknown():
    respx.get("https://isc.sans.edu/api/ip/198.51.100.1?json").mock(
        return_value=httpx.Response(200, json={"ip": {"count": None, "attacks": None}}))
    clean = await DShieldConnector().lookup(IOC(type=IOCType.IPV4, value="198.51.100.1"))
    assert clean is not None and clean.verdict is Verdict.BENIGN

    respx.get("https://isc.sans.edu/api/ip/198.51.100.2?json").mock(
        return_value=httpx.Response(503))
    down = await DShieldConnector().lookup(IOC(type=IOCType.IPV4, value="198.51.100.2"))
    assert down is not None and down.verdict is Verdict.UNKNOWN  # never raises


# ---------------------------------------------------------------- CIRCL


@pytest.mark.asyncio
@respx.mock
async def test_hashlookup_known_good_suppresses_false_positive():
    respx.get(f"https://hashlookup.circl.lu/lookup/sha256/{SHA}").mock(
        return_value=httpx.Response(200, json={
            "hashlookup:trust": 100, "ProductName": "Microsoft Windows",
        }))
    v = await CIRCLHashlookupConnector().lookup(IOC(type=IOCType.SHA256, value=SHA))
    assert v is not None and v.verdict is Verdict.BENIGN
    assert "Microsoft Windows" in (v.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_hashlookup_known_malicious_tag():
    respx.get(f"https://hashlookup.circl.lu/lookup/sha256/{SHA}").mock(
        return_value=httpx.Response(200, json={
            "KnownMalicious": ["snort", "cape"], "hashlookup:trust": 20,
        }))
    v = await CIRCLHashlookupConnector().lookup(IOC(type=IOCType.SHA256, value=SHA))
    assert v is not None and v.verdict is Verdict.MALICIOUS
    assert "snort" in (v.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_hashlookup_unknown_hash_is_no_signal():
    respx.get(f"https://hashlookup.circl.lu/lookup/sha256/{SHA}").mock(
        return_value=httpx.Response(404, json={"message": "Non existing"}))
    v = await CIRCLHashlookupConnector().lookup(IOC(type=IOCType.SHA256, value=SHA))
    assert v is not None and v.verdict is Verdict.UNKNOWN


# ---------------------------------------------------------------- builder


def test_live_mode_works_with_zero_api_keys(monkeypatch):
    """No paid/registered key configured -> keyless public feeds carry live mode
    (no silent mock fallback)."""
    from app.core.config import settings as cfg
    from app.engines.threat_intel.aggregator import build_aggregator

    monkeypatch.setattr(cfg, "connector_mode", type(cfg.connector_mode)("live"))
    for key in ("virustotal_api_key", "abuseipdb_api_key", "greynoise_api_key",
                "otx_api_key", "opencti_url", "opencti_token", "misp_url", "misp_key"):
        monkeypatch.setattr(cfg, key, "")

    names = {c.name for c in build_aggregator()._connectors}
    assert names == {"dshield", "circl-hashlookup"}

    monkeypatch.setattr(cfg, "ti_enable_public_feeds", False)
    names = {c.name for c in build_aggregator()._connectors}
    assert names == {"mock-ti"}  # explicit fallback, never empty enrichment
