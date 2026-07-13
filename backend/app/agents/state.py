"""Working memory of one autonomous investigation.

The state is the single source of truth the planner reads and the tools mutate.
Every collection is keyed/deduplicated so the loop converges: a tool that finds
nothing new leaves the state unchanged, and the planner then has nothing left
to schedule.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.engines.edr.base import EDRHit
from app.engines.email_investigation.base import EmailMessage
from app.schemas.alert import Alert
from app.schemas.common import Verdict
from app.schemas.investigation import Evidence, TimelineEvent
from app.schemas.ioc import IOC, EnrichedIOC


@dataclass
class InvestigationState:
    tenant: str
    alert: Alert
    text_corpus: str = ""

    # Email context (phishing path)
    email_msg: EmailMessage | None = None
    email_checked: bool = False
    affected_users: set[str] = field(default_factory=set)

    # IOC lifecycle: discovered -> enriched -> hunted
    extracted: bool = False
    pending_iocs: dict[str, IOC] = field(default_factory=dict)  # key -> IOC awaiting TI
    enriched: dict[str, EnrichedIOC] = field(default_factory=dict)
    hunted_keys: set[str] = field(default_factory=set)

    # Sandbox
    detonated: set[str] = field(default_factory=set)  # attachment sha256s
    sandbox_malscore: float = 0.0

    # EDR
    edr_hits: list[EDRHit] = field(default_factory=list)

    # Accumulated narrative inputs
    signals: list[str] = field(default_factory=list)
    timeline_groups: list[list[TimelineEvent]] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_iocs(self, iocs: list[IOC]) -> int:
        """Queue newly discovered IOCs for enrichment; returns how many were new."""
        new = 0
        for ioc in iocs:
            key = ioc.key()
            if key not in self.enriched and key not in self.pending_iocs:
                self.pending_iocs[key] = ioc
                new += 1
        return new

    def record_enrichment(self, results: list[EnrichedIOC]) -> None:
        for e in results:
            key = e.ioc.key()
            self.enriched[key] = e
            self.pending_iocs.pop(key, None)

    def malicious_unhunted(self) -> list[EnrichedIOC]:
        return [
            e for key, e in self.enriched.items()
            if e.verdict is Verdict.MALICIOUS and key not in self.hunted_keys
        ]

    def unhunted(self) -> list[EnrichedIOC]:
        return [e for key, e in self.enriched.items() if key not in self.hunted_keys]

    def looks_like_phishing(self) -> bool:
        text = (self.alert.title + " " + self.alert.description).lower()
        return "phish" in text or bool(self.alert.extra.get("message_id"))
