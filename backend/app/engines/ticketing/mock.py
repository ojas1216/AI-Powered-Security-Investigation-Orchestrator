"""Mock ticketing: returns a deterministic ticket ref without external calls."""
from __future__ import annotations

import hashlib

from app.core.config import settings
from app.engines.ticketing.base import TicketingConnector
from app.schemas.investigation import InvestigationPackage, TicketRef


class MockTicketing(TicketingConnector):
    name = "mock-ticketing"

    async def create_ticket(self, package: InvestigationPackage) -> TicketRef:
        digest = hashlib.sha1(package.investigation_id.encode(),
                             usedforsecurity=False).hexdigest()
        short = digest[:6].upper()
        return TicketRef(
            system="mock", ticket_id=f"SEC-{short}",
            url=f"https://tickets.local/SEC-{short}",
        )


def build_ticketing() -> TicketingConnector:
    if settings.use_mock_connectors:
        return MockTicketing()
    # Live ServiceNow/Jira connectors register here based on configured creds.
    return MockTicketing()
