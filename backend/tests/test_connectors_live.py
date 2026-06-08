"""Live threat-intel connectors, exercised offline with respx-mocked HTTP.

These verify the request shape, verdict mapping, and fail-safe behavior without
any real API keys or network. The SSRF DNS check is patched so the allow-list
logic still runs but no real resolution happens.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.engines.threat_intel.connectors.abuseipdb import AbuseIPDBConnector
from app.engines.threat_intel.connectors.greynoise import GreyNoiseConnector
from app.engines.threat_intel.connectors.otx import OTXConnector
from app.engines.threat_intel.connectors.virustotal import VirusTotalConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    # Keep the SSRF allow-list check, skip real DNS resolution.
    monkeypatch.setattr("app.core.ssrf._is_blocked_ip", lambda host: False)


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_malicious():
    respx.get(
        "https://www.virustotal.com/api/v3/domains/evil.com"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {
                "malicious": 12, "suspicious": 2, "harmless": 50, "undetected": 6}}}},
        )
    )
    sv = await VirusTotalConnector(api_key="k").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv is not None
    assert sv.verdict is Verdict.MALICIOUS
    assert 0 < sv.score <= 1


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_404_unknown():
    respx.get("https://www.virustotal.com/api/v3/domains/clean.example").mock(
        return_value=httpx.Response(404)
    )
    sv = await VirusTotalConnector(api_key="k").lookup(
        IOC(type=IOCType.DOMAIN, value="clean.example")
    )
    assert sv.verdict is Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_virustotal_no_key_returns_none():
    sv = await VirusTotalConnector(api_key="").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv is None


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_confidence_mapping():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 42}}
        )
    )
    sv = await AbuseIPDBConnector(api_key="k").lookup(
        IOC(type=IOCType.IPV4, value="45.155.205.99")
    )
    assert sv.verdict is Verdict.MALICIOUS
    assert sv.score == 0.9


@pytest.mark.asyncio
@respx.mock
async def test_greynoise_benign():
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        return_value=httpx.Response(
            200, json={"classification": "benign", "noise": True}
        )
    )
    sv = await GreyNoiseConnector(api_key="k").lookup(
        IOC(type=IOCType.IPV4, value="8.8.8.8")
    )
    assert sv.verdict is Verdict.BENIGN


@pytest.mark.asyncio
@respx.mock
async def test_otx_pulses_malicious():
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/evil.com/general"
    ).mock(return_value=httpx.Response(200, json={"pulse_info": {"count": 9}}))
    sv = await OTXConnector(api_key="k").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
@respx.mock
async def test_connector_never_raises_on_http_error():
    respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
        side_effect=httpx.ConnectError("boom")
    )
    sv = await GreyNoiseConnector(api_key="k").lookup(
        IOC(type=IOCType.IPV4, value="1.2.3.4")
    )
    # Fail-safe: a flaky provider yields UNKNOWN, not an exception.
    assert sv.verdict is Verdict.UNKNOWN
