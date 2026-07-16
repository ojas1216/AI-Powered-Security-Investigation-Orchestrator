"""Artifact parsers: turn a real file into the normalized Alert schema.

An analyst can drop an `.eml`, a Windows/Sysmon event export (`.xml`/`.json`),
or a `.csv` of alerts, and the platform produces an investigation — the file's
indicators land in the alert's `raw_text`/entities so the existing loop (IOC
extraction → TI → detection → …) runs unchanged.

All parsers are stdlib-only (no native deps), so ingestion stays hermetic and
air-gap-capable. Each raises `ParseError` on malformed input; the API maps that
to 422.
"""
from __future__ import annotations

import abc

from app.schemas.alert import Alert


class ParseError(Exception):
    """Artifact could not be parsed into an Alert."""


class ArtifactParser(abc.ABC):
    name: str = "base"
    #: file extensions this parser handles (lower-case, no dot)
    extensions: frozenset[str] = frozenset()

    @abc.abstractmethod
    def parse(self, content: bytes, *, filename: str) -> Alert:
        raise NotImplementedError


class ParserRegistry:
    def __init__(self) -> None:
        self._by_ext: dict[str, ArtifactParser] = {}

    def register(self, parser: ArtifactParser) -> None:
        for ext in parser.extensions:
            if ext in self._by_ext:
                raise ValueError(f"extension already registered: {ext}")
            self._by_ext[ext] = parser

    def for_filename(self, filename: str) -> ArtifactParser | None:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return self._by_ext.get(ext)

    def extensions(self) -> list[str]:
        return sorted(self._by_ext)
