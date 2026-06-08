"""Ticketing contract (ServiceNow / Jira)."""
from __future__ import annotations

import abc

from app.schemas.investigation import InvestigationPackage, TicketRef


class TicketingConnector(abc.ABC):
    name = "base-ticketing"

    @abc.abstractmethod
    async def create_ticket(self, package: InvestigationPackage) -> TicketRef:
        raise NotImplementedError

    @staticmethod
    def render_body(package: InvestigationPackage) -> str:
        """Human-readable ticket body assembled from the investigation package."""
        lines = [
            f"# Investigation {package.investigation_id}",
            f"Verdict: {package.overall_verdict.value.upper()}  "
            f"Risk: {package.risk.score if package.risk else 'n/a'} "
            f"({package.risk.severity.value if package.risk else 'n/a'})",
            "",
            f"## Alert\n{package.alert.title}",
            "",
            "## Key IOCs",
            *[
                f"- [{e.verdict.value}] {e.ioc.type.value}: {e.ioc.value} "
                f"(conf {e.confidence})"
                for e in package.iocs[:20]
            ],
            "",
            "## Affected",
            f"Hosts: {', '.join(package.affected_hosts) or 'none'}",
            f"Users: {', '.join(package.affected_users) or 'none'}",
            "",
            "## MITRE ATT&CK",
            *[f"- {t.technique_id} {t.name} ({t.tactic})" for t in package.mitre],
            "",
            "## Recommended actions",
            *[f"- [{s.phase}] {s.action}" for s in package.playbook],
            "",
            "## Executive summary",
            package.executive_summary,
        ]
        return "\n".join(lines)
