"""Windows / Sysmon event parser — exported JSON or XML (stdlib only).

Handles the two forms teams actually export from EVTX (raw binary .evtx needs a
native lib and is out of scope here): Windows Event Log / Sysmon **XML** and
**JSON**. Command lines, images, target files and registry paths are projected
into the alert's `raw_text`, so the built-in detection rules (encoded PowerShell,
LOLBins, run-key persistence, credential dumping, …) fire directly.
"""
from __future__ import annotations

import json
from xml.etree import ElementTree as ET

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_MAX = 200_000
# EventData fields that carry the interesting behavior.
_SIGNAL_FIELDS = {
    "CommandLine", "Image", "ParentCommandLine", "ParentImage", "TargetFilename",
    "TargetObject", "Details", "OriginalFileName", "Hashes", "QueryName",
    "DestinationIp", "DestinationHostname", "User", "SourceIp",
}


class WinEventParser(ArtifactParser):
    name = "winevent"
    extensions = frozenset({"xml", "json", "evtx"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        if filename.lower().endswith(".evtx"):
            raise ParseError(
                "raw binary .evtx is unsupported; export to XML or JSON first "
                "(e.g. `wevtutil qe … /f:xml` or Get-WinEvent | ConvertTo-Json)")
        text = content.decode("utf-8", errors="replace")
        stripped = text.lstrip()
        if stripped.startswith("<"):
            events = _parse_xml(text)
        else:
            events = _parse_json(text)
        if not events:
            raise ParseError("no Windows events found in artifact")

        hosts = sorted({e["host"] for e in events if e.get("host")})
        users = sorted({e["user"] for e in events if e.get("user")})
        event_ids = sorted({str(e["event_id"]) for e in events if e.get("event_id")})
        raw_text = "\n".join(e["raw"] for e in events)[:_MAX]
        title = (f"Windows event artifact: {len(events)} event(s) "
                 f"(IDs {', '.join(event_ids[:6])})")

        return Alert(
            source=SourceProduct.GENERIC,
            source_alert_id=filename[:256],
            title=title[:512],
            description=f"Parsed {len(events)} Windows/Sysmon event(s) from "
                        f"{filename}."[:8192],
            severity=Severity.MEDIUM,
            hosts=hosts,
            users=users,
            raw_text=raw_text,
            extra={"artifact": "winevent", "event_count": len(events),
                   "event_ids": event_ids},
        )


def _parse_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid event JSON: {exc}") from exc
    records = data if isinstance(data, list) else [data]
    events: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        # Accept both flat exports and {System:..., EventData:{...}} shapes.
        merged: dict = {}
        for k, v in rec.items():
            if isinstance(v, dict):
                merged.update(v)
            else:
                merged[k] = v
        events.append(_event_from_fields(merged))
    return events


def _parse_xml(text: str) -> list[dict]:
    # Defense against XXE / entity-expansion ("billion laughs"): event exports
    # never contain a DTD, so reject any inline/external entity definition before
    # parsing. With no DTD present, ElementTree cannot resolve entities.
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ParseError("XML with a DTD/entity declaration is not accepted")
    try:
        # Wrap so multiple <Event> siblings without a root still parse.
        # DTD/entity declarations are rejected above, so this parse is safe.
        root = ET.fromstring(f"<root>{_strip_ns(text)}</root>")  # noqa: S314  # nosec B314,B320
    except ET.ParseError as exc:
        raise ParseError(f"invalid event XML: {exc}") from exc
    events: list[dict] = []
    for ev in root.iter("Event"):
        fields: dict = {}
        system = ev.find("System")
        if system is not None:
            eid = system.find("EventID")
            if eid is not None and eid.text:
                fields["EventID"] = eid.text.strip()
            comp = system.find("Computer")
            if comp is not None and comp.text:
                fields["Computer"] = comp.text.strip()
        for data in ev.iter("Data"):
            name = data.get("Name")
            if name and data.text:
                fields[name] = data.text.strip()
        events.append(_event_from_fields(fields))
    return events


def _event_from_fields(fields: dict) -> dict:
    event_id = fields.get("EventID") or fields.get("Event ID") or fields.get("Id")
    host = fields.get("Computer") or fields.get("Hostname") or fields.get("host")
    user = (fields.get("User") or fields.get("SubjectUserName")
            or fields.get("TargetUserName"))
    parts = [f"EventID={event_id}" if event_id else ""]
    for key in _SIGNAL_FIELDS:
        if fields.get(key):
            parts.append(f"{key}={fields[key]}")
    raw = " ".join(p for p in parts if p) or json.dumps(fields, default=str)
    return {"event_id": event_id, "host": host, "user": user, "raw": raw}


def _strip_ns(text: str) -> str:
    # Windows event XML declares a default namespace; drop it so tag names match.
    return text.replace(
        ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', "")
