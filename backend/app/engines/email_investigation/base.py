"""Email investigation contract (M365 / Workspace / Mimecast / Proofpoint)."""
from __future__ import annotations

import abc
from datetime import datetime

from pydantic import BaseModel, Field


class EmailAttachment(BaseModel):
    filename: str
    sha256: str
    content_type: str = "application/octet-stream"


class EmailMessage(BaseModel):
    message_id: str
    subject: str
    sender: str
    recipients: list[str] = Field(default_factory=list)
    received_at: datetime
    body: str = ""
    urls: list[str] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)


class EmailConnector(abc.ABC):
    name = "base-email"

    @abc.abstractmethod
    async def get_message(self, message_id: str) -> EmailMessage:
        raise NotImplementedError

    @abc.abstractmethod
    async def find_recipients(self, message_id: str) -> list[str]:
        """Mailbox-wide trace: everyone who received this campaign."""
        raise NotImplementedError
