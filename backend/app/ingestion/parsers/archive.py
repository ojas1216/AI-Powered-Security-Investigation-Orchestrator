"""ZIP archive parser — extract text from every member (stdlib zipfile).

Aggregates recoverable text across archive members (decoding text-like members,
recovering printable strings from binary ones) into one Alert, so an uploaded
bundle of evidence is investigated as a whole. Bounded against zip bombs (member
count, per-member and total decompressed size caps); nested archives are noted
but not recursed.
"""
from __future__ import annotations

import io
import re
import zipfile

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_TEXT_EXT = (".txt", ".csv", ".tsv", ".json", ".xml", ".eml", ".log", ".yara",
             ".sigma", ".ioc", ".md")
_MAX_TEXT = 300_000
_MAX_MEMBERS = 500
_MAX_MEMBER_BYTES = 10 * 1024 * 1024
_MAX_TOTAL = 40 * 1024 * 1024


class ZipParser(ArtifactParser):
    name = "zip"
    extensions = frozenset({"zip"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile as exc:
            raise ParseError(f"not a valid zip archive: {exc}") from exc

        parts: list[str] = []
        names: list[str] = []
        total = 0
        for info in zf.infolist()[:_MAX_MEMBERS]:
            if info.is_dir() or info.file_size > _MAX_MEMBER_BYTES:
                continue
            total += info.file_size
            if total > _MAX_TOTAL:
                break
            names.append(info.filename)
            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError):
                continue  # encrypted / corrupt member — skip, don't fail the whole zip
            lower = info.filename.lower()
            if lower.endswith(_TEXT_EXT):
                parts.append(data.decode("utf-8", "replace"))
            elif lower.endswith(".zip"):
                parts.append(f"[nested archive: {info.filename}]")
            else:
                parts.append(b" ".join(_STRINGS.findall(data)).decode("latin-1",
                                                                      "replace"))

        text = re.sub(r"\s+", " ", " ".join(parts)).strip()[:_MAX_TEXT]
        if not text:
            raise ParseError("no extractable content in the archive")
        return Alert(
            source=SourceProduct.GENERIC, source_alert_id=filename[:256],
            title=f"Archive: {filename} ({len(names)} files)"[:512],
            description=f"Aggregated evidence from {len(names)} member(s)"[:8192],
            severity=Severity.MEDIUM, raw_text=text,
            extra={"artifact": "zip", "members": names[:50]})
