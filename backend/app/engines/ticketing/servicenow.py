"""ServiceNow connector (live). Creates a security incident via Table API."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.ticketing.base import TicketingConnector
from app.schemas.common import Severity
from app.schemas.investigation import InvestigationPackage, TicketRef

log = get_logger("ticketing.servicenow")

_IMPACT = {Severity.CRITICAL: 1, Severity.HIGH: 2, Severity.MEDIUM: 3, Severity.LOW: 3}


class ServiceNowConnector(TicketingConnector):
    name = "servicenow"

    async def create_ticket(self, package: InvestigationPackage) -> TicketRef:
        base = settings.servicenow_instance.rstrip("/")
        sev = package.risk.severity if package.risk else Severity.MEDIUM
        payload = {
            "short_description": f"[AegisFlow] {package.alert.title}",
            "description": self.render_body(package),
            "impact": _IMPACT.get(sev, 3),
            "urgency": _IMPACT.get(sev, 3),
            "category": "security",
        }
        auth = (settings.servicenow_user, settings.servicenow_password)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{base}/api/now/table/incident", json=payload, auth=auth
            )
            resp.raise_for_status()
            result = resp.json()["result"]
        number = result.get("number", "UNKNOWN")
        return TicketRef(system="servicenow", ticket_id=number,
                         url=f"{base}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}")
