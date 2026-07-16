"""Expanded upload workspace: .docx / .xlsx / .pdf / .pcap / .zip parsers."""
from __future__ import annotations

import base64
import io
import zipfile

import pytest

from app.ingestion.parsers import ParseError, parse_artifact, supported_extensions


def make_docx(body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   f"<w:document><w:body><w:t>{body}</w:t></w:body></w:document>")
    return buf.getvalue()


def make_xlsx(*cells: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        shared = "".join(f"<si><t>{c}</t></si>" for c in cells)
        z.writestr("xl/sharedStrings.xml", f"<sst>{shared}</sst>")
        z.writestr("xl/worksheets/sheet1.xml", "<worksheet/>")
    return buf.getvalue()


def make_zip(**files: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


# ---------------------------------------------------------------- office


def test_docx_extracts_text_and_iocs():
    alert = parse_artifact("report.docx",
                           make_docx("Please pay at https://evil.com/pay now"))
    assert "evil.com" in alert.raw_text
    assert alert.extra["artifact"] == "docx"


def test_xlsx_extracts_cells():
    alert = parse_artifact("iocs.xlsx", make_xlsx("45.155.205.99", "malware-c2.net"))
    assert "45.155.205.99" in alert.raw_text and "malware-c2.net" in alert.raw_text


def test_docx_invalid_zip_errors():
    with pytest.raises(ParseError, match="OOXML"):
        parse_artifact("bad.docx", b"not a zip")


@pytest.mark.asyncio
async def test_docx_runs_full_investigation():
    from app.orchestrator import run_investigation

    alert = parse_artifact("phish.docx", make_docx("click https://evil.com/pay"))
    pkg = await run_investigation("acme", alert)
    assert pkg.overall_verdict.value == "malicious"


# ---------------------------------------------------------------- pdf


def test_pdf_strings_extraction():
    pdf = b"%PDF-1.7\n... stream ... http://malware-c2.net/gate.php ... endstream"
    alert = parse_artifact("invoice.pdf", pdf)
    assert "malware-c2.net" in alert.raw_text
    assert alert.extra["artifact"] == "pdf"


def test_pdf_without_header_errors():
    with pytest.raises(ParseError, match="%PDF"):
        parse_artifact("fake.pdf", b"just text with evil.com")


# ---------------------------------------------------------------- pcap


def test_pcap_magic_and_strings():
    # pcap little-endian magic + an ascii domain in the "packet"
    pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"malware-c2.net" + b"\x00" * 8
    alert = parse_artifact("capture.pcap", pcap)
    assert "malware-c2.net" in alert.raw_text
    assert alert.extra["artifact"] == "pcap"


def test_pcap_bad_magic_errors():
    with pytest.raises(ParseError, match="magic"):
        parse_artifact("x.pcapng", b"nope")


# ---------------------------------------------------------------- zip


def test_zip_aggregates_members():
    alert = parse_artifact("evidence.zip", make_zip(**{
        "note.txt": "beacon to 45.155.205.99",
        "urls.csv": "url\nhttps://evil.com/pay",
    }))
    assert "45.155.205.99" in alert.raw_text and "evil.com" in alert.raw_text
    assert alert.extra["artifact"] == "zip"
    assert "note.txt" in alert.extra["members"]


def test_zip_bad_archive_errors():
    with pytest.raises(ParseError, match="valid zip"):
        parse_artifact("x.zip", b"not a zip")


# ---------------------------------------------------------------- registry + API


def test_new_extensions_registered():
    exts = set(supported_extensions())
    assert {"docx", "xlsx", "pdf", "pcap", "pcapng", "zip"} <= exts


def test_ingest_docx_via_api(client):
    headers = {"X-Tenant-ID": "acme", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    b64 = base64.b64encode(make_docx("payment at https://evil.com/pay")).decode()
    resp = client.post("/api/v1/alerts/ingest-file", headers=headers,
                       json={"filename": "phish.docx", "content_b64": b64})
    assert resp.status_code == 201, resp.text
    assert resp.json()["overall_verdict"] == "malicious"
