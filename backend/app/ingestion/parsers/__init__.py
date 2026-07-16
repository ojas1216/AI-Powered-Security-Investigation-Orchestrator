"""Artifact parsers: files (.eml/.xml/.json/.csv/.txt) → Alert."""
from __future__ import annotations

from app.ingestion.parsers.archive import ZipParser
from app.ingestion.parsers.base import ArtifactParser, ParseError, ParserRegistry
from app.ingestion.parsers.binary import PcapParser, PdfParser
from app.ingestion.parsers.csv_alerts import CsvParser
from app.ingestion.parsers.eml import EmlParser
from app.ingestion.parsers.office import DocxParser, XlsxParser
from app.ingestion.parsers.winevent import WinEventParser
from app.schemas.alert import Alert

__all__ = [
    "ArtifactParser",
    "ParseError",
    "ParserRegistry",
    "parse_artifact",
    "supported_extensions",
]

_registry = ParserRegistry()
_registry.register(EmlParser())
_registry.register(WinEventParser())
_registry.register(CsvParser())
_registry.register(DocxParser())
_registry.register(XlsxParser())
_registry.register(PdfParser())
_registry.register(PcapParser())
_registry.register(ZipParser())


def parse_artifact(filename: str, content: bytes) -> Alert:
    """Parse an uploaded artifact into an Alert. Raises ParseError."""
    parser = _registry.for_filename(filename)
    if parser is None:
        raise ParseError(
            f"unsupported artifact type: {filename} "
            f"(supported: {', '.join(_registry.extensions())})")
    return parser.parse(content, filename=filename)


def supported_extensions() -> list[str]:
    return _registry.extensions()
