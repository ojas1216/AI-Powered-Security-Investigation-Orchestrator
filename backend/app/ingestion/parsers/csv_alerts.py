"""CSV / TXT artifact parser (stdlib `csv`).

A CSV of alerts or IOCs becomes one Alert whose `raw_text` aggregates the rows
(so every indicator in the file is extracted and enriched) and whose entities
are pulled from recognizable columns (ip/user/host/title/description). Plain
`.txt` is treated as free text.
"""
from __future__ import annotations

import csv
import io

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_MAX = 200_000
_MAX_ROWS = 5000

_TITLE_COLS = ("title", "name", "alert", "rule", "signature")
_DESC_COLS = ("description", "message", "details", "summary")
_IP_COLS = ("src_ip", "source_ip", "srcip", "dst_ip", "dest_ip", "destination_ip",
            "ip", "ipaddress")
_USER_COLS = ("user", "username", "account", "user_name")
_HOST_COLS = ("host", "hostname", "computer", "device", "endpoint")


class CsvParser(ArtifactParser):
    name = "csv"
    extensions = frozenset({"csv", "tsv", "txt"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        text = content.decode("utf-8", errors="replace")
        if filename.lower().endswith(".txt"):
            return _text_alert(text, filename)

        delimiter = "\t" if filename.lower().endswith(".tsv") else ","
        try:
            reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
            rows = [r for _, r in zip(range(_MAX_ROWS), reader, strict=False)]
        except csv.Error as exc:
            raise ParseError(f"invalid CSV: {exc}") from exc
        if not rows:
            raise ParseError("CSV has no data rows")

        headers = {h.lower().strip(): h for h in (reader.fieldnames or [])}
        users: set[str] = set()
        hosts: set[str] = set()
        title = ""
        description = ""
        raw_lines: list[str] = []

        for row in rows:
            raw_lines.append(" ".join(str(v) for v in row.values() if v))
            if not title:
                title = _first(row, headers, _TITLE_COLS)
            if not description:
                description = _first(row, headers, _DESC_COLS)
            for col in _USER_COLS:
                if col in headers and row.get(headers[col]):
                    users.add(row[headers[col]].strip())
            for col in _HOST_COLS:
                if col in headers and row.get(headers[col]):
                    hosts.add(row[headers[col]].strip())

        return Alert(
            source=SourceProduct.GENERIC,
            source_alert_id=filename[:256],
            title=(title or f"CSV artifact: {filename} ({len(rows)} rows)")[:512],
            description=(description or f"{len(rows)} rows parsed from {filename}")[:8192],
            severity=Severity.MEDIUM,
            users=sorted(users),
            hosts=sorted(hosts),
            raw_text="\n".join(raw_lines)[:_MAX],
            extra={"artifact": "csv", "row_count": len(rows)},
        )


def _first(row: dict, headers: dict[str, str], cols: tuple[str, ...]) -> str:
    for col in cols:
        if col in headers and row.get(headers[col]):
            return str(row[headers[col]]).strip()
    return ""


def _text_alert(text: str, filename: str) -> Alert:
    if not text.strip():
        raise ParseError("empty text artifact")
    return Alert(
        source=SourceProduct.GENERIC,
        source_alert_id=filename[:256],
        title=f"Text artifact: {filename}"[:512],
        description=f"Free-text artifact {filename}"[:8192],
        severity=Severity.MEDIUM,
        raw_text=text[:_MAX],
        extra={"artifact": "txt"},
    )
