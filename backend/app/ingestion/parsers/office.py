"""Office document parsers — .docx and .xlsx (stdlib zipfile + XML).

OOXML documents are ZIP archives of XML parts; we unzip in-memory and strip tags
to recover the text, then project it into an Alert so IOC extraction runs over
the document body. No third-party dependency, fully offline. Bounded against
zip-bomb abuse (member count + decompressed size caps).
"""
from __future__ import annotations

import io
import re
import zipfile

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_TAG = re.compile(r"<[^>]+>")
_MAX_TEXT = 200_000
_MAX_MEMBERS = 500
_MAX_UNCOMPRESSED = 25 * 1024 * 1024


def _xml_text(content: bytes, prefixes: tuple[str, ...]) -> str:
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise ParseError(f"not a valid OOXML (zip) document: {exc}") from exc
    total = 0
    parts: list[str] = []
    for info in zf.infolist()[:_MAX_MEMBERS]:
        if not info.filename.endswith(".xml"):
            continue
        if not any(info.filename.startswith(p) for p in prefixes):
            continue
        total += info.file_size
        if total > _MAX_UNCOMPRESSED:
            break
        xml = zf.read(info.filename).decode("utf-8", "replace")
        parts.append(_TAG.sub(" ", xml))
    text = " ".join(parts)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        raise ParseError("no extractable text in the document")
    return text[:_MAX_TEXT]


class DocxParser(ArtifactParser):
    name = "docx"
    extensions = frozenset({"docx"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        text = _xml_text(content, ("word/",))
        return Alert(
            source=SourceProduct.GENERIC, source_alert_id=filename[:256],
            title=f"Word document: {filename}"[:512],
            description=f"Text extracted from {filename}"[:8192],
            severity=Severity.MEDIUM, raw_text=text,
            extra={"artifact": "docx"})


class XlsxParser(ArtifactParser):
    name = "xlsx"
    extensions = frozenset({"xlsx"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        text = _xml_text(content, ("xl/",))
        return Alert(
            source=SourceProduct.GENERIC, source_alert_id=filename[:256],
            title=f"Excel workbook: {filename}"[:512],
            description=f"Cell text extracted from {filename}"[:8192],
            severity=Severity.MEDIUM, raw_text=text,
            extra={"artifact": "xlsx"})
