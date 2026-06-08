"""Jira connector (live). Creates a security issue via REST v3."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.engines.ticketing.base import TicketingConnector
from app.schemas.investigation import InvestigationPackage, TicketRef


class JiraConnector(TicketingConnector):
    name = "jira"

    def __init__(self, project_key: str = "SEC") -> None:
        self._project = project_key

    async def create_ticket(self, package: InvestigationPackage) -> TicketRef:
        base = settings.jira_url.rstrip("/")
        payload = {
            "fields": {
                "project": {"key": self._project},
                "summary": f"[AegisFlow] {package.alert.title}",
                "description": self.render_body(package),
                "issuetype": {"name": "Bug"},
            }
        }
        auth = (settings.jira_user, settings.jira_token)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{base}/rest/api/3/issue", json=payload, auth=auth)
            resp.raise_for_status()
            key = resp.json()["key"]
        return TicketRef(system="jira", ticket_id=key, url=f"{base}/browse/{key}")
