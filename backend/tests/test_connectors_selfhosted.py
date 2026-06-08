"""Self-hosted connectors (OpenCTI, MISP, CAPE) exercised offline with respx.

Base URLs/tokens are injected via constructor, so no config or network is needed.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.engines.sandbox.cape import CAPESandbox
from app.engines.threat_intel.connectors.misp import MISPConnector
from app.engines.threat_intel.connectors.opencti import OpenCTIConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.ioc import IOC


@pytest.mark.asyncio
@respx.mock
async def test_opencti_high_score_malicious():
    respx.post("https://opencti.test/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"stixCoreObjects": {"edges": [
                {"node": {"x_opencti_score": 90}}]}}},
        )
    )
    sv = await OpenCTIConnector(url="https://opencti.test", token="t").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv.verdict is Verdict.MALICIOUS
    assert sv.score == 0.9


@pytest.mark.asyncio
@respx.mock
async def test_opencti_no_match_unknown():
    respx.post("https://opencti.test/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"stixCoreObjects": {"edges": []}}})
    )
    sv = await OpenCTIConnector(url="https://opencti.test", token="t").lookup(
        IOC(type=IOCType.DOMAIN, value="clean.example")
    )
    assert sv.verdict is Verdict.UNKNOWN


@pytest.mark.asyncio
@respx.mock
async def test_misp_to_ids_malicious():
    respx.post("https://misp.test/attributes/restSearch").mock(
        return_value=httpx.Response(
            200,
            json={"response": {"Attribute": [
                {"value": "evil.com", "to_ids": True},
                {"value": "evil.com", "to_ids": False},
            ]}},
        )
    )
    sv = await MISPConnector(url="https://misp.test", key="k").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_misp_no_key_returns_none():
    sv = await MISPConnector(url="", key="").lookup(
        IOC(type=IOCType.DOMAIN, value="evil.com")
    )
    assert sv is None


@pytest.mark.asyncio
@respx.mock
async def test_cape_url_detonation_malicious():
    base = "https://cape.test"
    respx.post(f"{base}/apiv2/tasks/create/url/").mock(
        return_value=httpx.Response(200, json={"data": {"task_ids": [42]}})
    )
    respx.get(f"{base}/apiv2/tasks/status/42/").mock(
        return_value=httpx.Response(200, json={"data": "reported"})
    )
    respx.get(f"{base}/apiv2/tasks/get/report/42/").mock(
        return_value=httpx.Response(200, json={"data": {
            "malscore": 8.0,
            "signatures": [
                {"description": "Spawns PowerShell"},
                {"description": "Creates Run key for persistence"},
            ],
            "behavior": {"processtree": [
                {"pid": 1000, "process_name": "winword.exe", "children": [
                    {"pid": 1040, "process_name": "powershell.exe", "children": []}]}]},
            "network": {"domains": [{"domain": "malware-c2.net"}]},
        }})
    )
    sandbox = CAPESandbox(url=base, token="t", poll_interval=0, max_polls=3)
    report = await sandbox.detonate(filename="Invoice.lnk", url="https://evil.com/pay")
    assert report.verdict == "malicious"
    assert report.malscore == 0.8
    assert report.process_tree is not None
    assert report.process_tree.name == "winword.exe"
    assert any("malware-c2.net" == i.value for i in report.dropped_iocs)
    assert report.persistence  # the Run-key signature was classified as persistence


@pytest.mark.asyncio
@respx.mock
async def test_cape_nothing_to_submit_is_nonblocking():
    # No url and no content → unknown report, not an exception (pipeline must not break).
    sandbox = CAPESandbox(url="https://cape.test", token="t")
    report = await sandbox.detonate(filename="nobytes.bin")
    assert report.verdict == "unknown"
    assert report.malscore == 0.0
