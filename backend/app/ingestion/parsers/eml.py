"""RFC-822 email (.eml / Outlook-exported) parser — stdlib `email`.

Extracts subject, sender, recipients, the text body, URLs and attachment
metadata (name + SHA-256), and projects them into an Alert whose title/body/
raw_text carry the indicators so IOC extraction and the phishing path fire.
"""
from __future__ import annotations

import hashlib
from email import message_from_bytes
from email.message import Message

from app.ingestion.parsers.base import ArtifactParser, ParseError
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_MAX_BODY = 100_000


class EmlParser(ArtifactParser):
    name = "eml"
    extensions = frozenset({"eml", "msg"})

    def parse(self, content: bytes, *, filename: str) -> Alert:
        try:
            msg = message_from_bytes(content)
        except Exception as exc:  # pragma: no cover - defensive
            raise ParseError(f"invalid email: {exc}") from exc

        subject = _header(msg, "Subject") or "(no subject)"
        sender = _header(msg, "From")
        to = _addresses(msg, "To") + _addresses(msg, "Cc")
        message_id = _header(msg, "Message-ID") or filename
        body = _text_body(msg)
        attachments = _attachments(msg)

        att_desc = ", ".join(f"{a['filename']} ({a['sha256'][:12]}…)"
                             for a in attachments)
        description = (f"Reported email from {sender or 'unknown'}. "
                       f"Attachments: {att_desc or 'none'}.")
        # raw_text carries body + headers so extract_iocs finds urls/domains/ips.
        raw_text = "\n".join([
            f"Subject: {subject}",
            f"From: {sender}",
            f"To: {', '.join(to)}",
            body,
        ])[:_MAX_BODY]

        return Alert(
            source=SourceProduct.GENERIC,
            source_alert_id=str(message_id).strip("<>")[:256],
            title=f"Reported email: {subject}"[:512],
            description=description[:8192],
            severity=Severity.MEDIUM,
            users=to,
            raw_text=raw_text,
            extra={
                "artifact": "eml",
                "message_id": str(message_id).strip("<>"),
                "sender": sender,
                "attachments": attachments,
            },
        )


def _header(msg: Message, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value else ""


def _addresses(msg: Message, name: str) -> list[str]:
    raw = msg.get(name)
    if not raw:
        return []
    from email.utils import getaddresses

    return [addr for _, addr in getaddresses([str(raw)]) if addr]


def _text_body(msg: Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not _is_attachment(part):
                return _decode(part)
        for part in msg.walk():  # fall back to any text/html
            if part.get_content_type() == "text/html" and not _is_attachment(part):
                return _decode(part)
        return ""
    return _decode(msg)


def _decode(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return str(part.get_payload())
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    return (part.get_content_disposition() == "attachment"
            or bool(part.get_filename()))


def _attachments(msg: Message) -> list[dict]:
    out: list[dict] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        fn = part.get_filename()
        if not fn:
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({
            "filename": fn,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "content_type": part.get_content_type(),
        })
    return out
