"""Mock email connector providing a realistic phishing message + recipient blast."""
from __future__ import annotations

from datetime import UTC, datetime

from app.core.config import settings
from app.engines.email_investigation.base import (
    EmailAttachment,
    EmailConnector,
    EmailMessage,
)


class MockEmail(EmailConnector):
    name = "mock-email"

    async def get_message(self, message_id: str) -> EmailMessage:
        return EmailMessage(
            message_id=message_id,
            subject="Outstanding Invoice — Immediate Payment Required",
            sender="billing@evil.com",
            recipients=["jdoe@acme.example", "asmith@acme.example"],
            received_at=datetime(2026, 6, 8, 8, 11, tzinfo=UTC),
            body=(
                "Please review the attached invoice and click "
                "hxxps://evil[.]com/pay to settle immediately."
            ),
            urls=["https://evil.com/pay"],
            attachments=[
                EmailAttachment(
                    filename="Invoice_8841.lnk",
                    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
            ],
        )

    async def find_recipients(self, message_id: str) -> list[str]:
        return [
            "jdoe@acme.example",
            "asmith@acme.example",
            "bwong@acme.example",
            "finance-dl@acme.example",
        ]


def build_email() -> EmailConnector:
    if settings.use_mock_connectors:
        return MockEmail()
    return MockEmail()
