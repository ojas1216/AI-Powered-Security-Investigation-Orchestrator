"""Binary artifact parsers — .pdf and .pcap/.pcapng (printable-string extraction).

Full PDF text or packet dissection needs heavy native libraries; instead we
recover printable strings from the raw bytes — which reliably surfaces the URLs,
domains, IPs and hashes IOC extraction cares about (a phishing PDF's link, a
pcap's DNS queries / HTTP Host / TLS SNI) — with no third-party dependency and
fully offline. Best-effort by design; a deployment wanting full text can add a
PDF/pcap library behind the same parser interface.
"""
from __future__ import annotations

import re

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_MAX_TEXT = 200_000


def _strings(data: bytes) -> str:
    joined = b" ".join(_STRINGS.findall(data))
    text = joined.decode("latin-1", "replace")
    if not text.strip():
        raise ParseError("no readable content extracted from the artifact")
    return text[:_MAX_TEXT]


class PdfParser(ArtifactParser):
    name = "pdf"
    extensions = frozenset({"pdf"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        if not content.lstrip().startswith(b"%PDF"):
            raise ParseError("not a PDF (missing %PDF header)")
        return Alert(
            source=SourceProduct.GENERIC, source_alert_id=filename[:256],
            title=f"PDF document: {filename}"[:512],
            description=f"Strings extracted from {filename} (best-effort)"[:8192],
            severity=Severity.MEDIUM, raw_text=_strings(content),
            extra={"artifact": "pdf"})


class PcapParser(ArtifactParser):
    name = "pcap"
    extensions = frozenset({"pcap", "pcapng"})

    #: pcap (LE/BE) + pcapng magic numbers
    _MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")

    def parse(self, content: bytes, *, filename: str) -> Alert:
        if not content.startswith(self._MAGICS):
            raise ParseError("not a pcap/pcapng capture (bad magic)")
        return Alert(
            source=SourceProduct.GENERIC, source_alert_id=filename[:256],
            title=f"Packet capture: {filename}"[:512],
            description=f"Network indicators extracted from {filename} "
                        "(strings; add a pcap library for full dissection)"[:8192],
            severity=Severity.MEDIUM, raw_text=_strings(content),
            extra={"artifact": "pcap"})
