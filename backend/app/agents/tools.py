"""Typed tool registry for the autonomous investigator.

Each tool wraps one engine behind a uniform async contract:

    run(state, **params) -> observation summary (str)

Tools mutate the shared InvestigationState (that's the "observe" half of the
plan-act-observe loop) and return a short human-readable observation that lands
in the explainability trace. Failures never abort the investigation: the loop
catches them, records them, and the planner works with whatever evidence exists.
"""
from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.agents.state import InvestigationState
from app.core.logging import get_logger
from app.engines.copilot import Copilot
from app.engines.detection import (
    DetectionEngine,
    RuleStore,
    build_detection_engine,
    build_rule_store,
)
from app.engines.edr.base import EDRConnector
from app.engines.email_investigation.base import EmailConnector
from app.engines.evidence.store import EvidenceStore
from app.engines.ioc_extraction import extract_iocs
from app.engines.sandbox.base import SandboxConnector
from app.engines.threat_intel.aggregator import ThreatIntelAggregator
from app.engines.ticketing.base import TicketingConnector
from app.schemas.common import IOCType, Verdict
from app.schemas.investigation import TimelineEvent
from app.schemas.ioc import IOC

log = get_logger("agents.tools")

ToolFn = Callable[..., Awaitable[str]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    fn: ToolFn


class ToolRegistry:
    """Name -> tool lookup with strict registration (no silent overwrite)."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, description: str, fn: ToolFn) -> None:
        if name in self._tools:
            raise ValueError(f"tool already registered: {name}")
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(f"tool {name} must be async")
        self._tools[name] = ToolSpec(name=name, description=description, fn=fn)

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"unknown tool: {name}") from None

    def names(self) -> list[str]:
        return sorted(self._tools)


class Toolbox:
    """Concrete investigation tools bound to engine instances (DI-friendly)."""

    def __init__(
        self,
        *,
        ti: ThreatIntelAggregator,
        sandbox: SandboxConnector,
        edr: EDRConnector,
        email: EmailConnector,
        evidence: EvidenceStore,
        copilot: Copilot,
        ticketing: TicketingConnector,
        detection: DetectionEngine | None = None,
        rule_store: RuleStore | None = None,
    ) -> None:
        self.ti = ti
        self.sandbox = sandbox
        self.edr = edr
        self.email = email
        self.evidence = evidence
        self.copilot = copilot
        self.ticketing = ticketing
        self.detection = detection or build_detection_engine()
        self.rule_store = rule_store or build_rule_store()

        # Specialist agents wrap the *injected* engines, so the loop's tools and
        # the /agents API share one implementation per capability (no duplication)
        # and test-injected engines (e.g. a broken EDR) flow through unchanged.
        from app.agents.specialists import (
            DetectionAgent,
            EdrHuntAgent,
            EmailAgent,
            IocExtractionAgent,
            SandboxAgent,
            ThreatIntelAgent,
        )

        self.ioc_agent = IocExtractionAgent()
        self.ti_agent = ThreatIntelAgent(self.ti)
        self.edr_agent = EdrHuntAgent(self.edr)
        self.sandbox_agent = SandboxAgent(self.sandbox)
        self.email_agent = EmailAgent(self.email)
        self.detection_agent = DetectionAgent(self.detection, self.rule_store)

        self.registry = ToolRegistry()
        self.registry.register(
            "run_detections",
            "Evaluate built-in + tenant detection rules against the alert",
            self.run_detections,
        )
        self.registry.register(
            "fetch_email_context",
            "Pull the reported email, campaign recipients, urls and attachments",
            self.fetch_email_context,
        )
        self.registry.register(
            "extract_iocs",
            "Extract defanged/fanged IOCs from all gathered text plus source entities",
            self.extract_iocs_tool,
        )
        self.registry.register(
            "enrich_iocs",
            "Fan out pending IOCs to threat-intel connectors and fuse verdicts",
            self.enrich_iocs,
        )
        self.registry.register(
            "detonate_attachment",
            "Detonate an email attachment in the sandbox; fold dropped IOCs back in",
            self.detonate_attachment,
        )
        self.registry.register(
            "hunt_edr",
            "Hunt IOCs across EDR telemetry to confirm on-host activity",
            self.hunt_edr,
        )

    async def run_detections(self, state: InvestigationState) -> str:
        tenant_rules = self.rule_store.list(state.tenant)
        matches = self.detection_agent.evaluate(state.alert, extra_rules=tenant_rules)
        state.detections = matches
        state.detections_ran = True
        # Rule titles are behavioral signals; the keyword MITRE mapper benefits too.
        state.signals.extend(m.title for m in matches)
        if matches:
            state.evidence.append(self.evidence.put_json(
                state.tenant, "detection_matches", "detections",
                [m.model_dump() for m in matches]))
        worst = matches[0].severity.value if matches else "none"
        return (f"{len(matches)} rule(s) fired "
                f"(worst severity: {worst}) out of "
                f"{len(self.detection.rules()) + len(tenant_rules)} evaluated")

    async def fetch_email_context(self, state: InvestigationState) -> str:
        msg_id = str(state.alert.extra.get("message_id", state.alert.source_alert_id))
        msg = await self.email_agent.get_message(msg_id)
        state.email_msg = msg
        state.email_checked = True
        state.text_corpus += "\n" + msg.body + "\n" + "\n".join(msg.urls)
        recipients = await self.email_agent.find_recipients(msg_id)
        state.affected_users |= set(recipients) | set(state.alert.users)
        state.timeline_groups.append([
            TimelineEvent(timestamp=msg.received_at, actor=msg.sender,
                          action="Email delivered", detail=msg.subject, source="email")
        ])
        state.evidence.append(self.evidence.put_json(
            state.tenant, "email_artifact", "original_email", msg.model_dump()))
        # New text arrived -> IOC extraction must run again over the wider corpus.
        state.extracted = False
        return (f"email '{msg.subject}' from {msg.sender}: "
                f"{len(recipients)} recipients, {len(msg.urls)} urls, "
                f"{len(msg.attachments)} attachments")

    async def extract_iocs_tool(self, state: InvestigationState) -> str:
        iocs = self.ioc_agent.extract(state.text_corpus)
        iocs = _merge_source_entities(iocs, state)
        new = state.add_iocs(iocs)
        state.extracted = True
        return f"{len(iocs)} IOCs in corpus, {new} new"

    async def enrich_iocs(self, state: InvestigationState) -> str:
        batch = list(state.pending_iocs.values())
        if not batch:
            return "nothing pending"
        results = await self.ti_agent.enrich(batch)
        state.record_enrichment(results)
        for e in results:
            if e.verdict is not Verdict.UNKNOWN:
                state.evidence.append(self.evidence.put_json(
                    state.tenant, "ti_result", f"ti:{e.ioc.value}", e.model_dump()))
        mal = sum(1 for e in results if e.verdict is Verdict.MALICIOUS)
        sus = sum(1 for e in results if e.verdict is Verdict.SUSPICIOUS)
        return f"enriched {len(results)} IOCs: {mal} malicious, {sus} suspicious"

    async def detonate_attachment(self, state: InvestigationState, *,
                                  filename: str, sha256: str) -> str:
        report = await self.sandbox_agent.detonate(filename=filename)
        state.detonated.add(sha256)
        state.sandbox_malscore = max(state.sandbox_malscore, report.malscore)
        state.signals.extend(report.signatures)
        state.signals.extend(report.persistence)
        new = state.add_iocs(report.dropped_iocs) if report.dropped_iocs else 0
        state.evidence.append(self.evidence.put_json(
            state.tenant, "sandbox_report", filename, report.model_dump()))
        if report.malscore > 0.5:
            state.timeline_groups.append([
                TimelineEvent(timestamp=datetime.now(UTC),
                              action="Attachment detonated: malicious",
                              detail=filename, source="sandbox")
            ])
        return (f"{filename}: malscore={report.malscore:.2f}, "
                f"{len(report.signatures)} signatures, {new} new dropped IOCs")

    async def hunt_edr(self, state: InvestigationState, *, ioc_keys: list[str]) -> str:
        targets = [state.enriched[k].ioc for k in ioc_keys if k in state.enriched]
        if not targets:
            return "no hunt targets"
        hits = await self.edr_agent.hunt(targets)
        state.hunted_keys |= set(ioc_keys)
        state.edr_hits.extend(hits)
        if hits:
            state.evidence.append(self.evidence.put_json(
                state.tenant, "edr_telemetry", "edr_hits",
                [h.model_dump() for h in hits]))
            state.timeline_groups.append([
                TimelineEvent(timestamp=h.observed_at, actor=h.user,
                              action="IOC observed on host",
                              detail=f"{h.host}: {h.ioc.value}", source="edr")
                for h in hits
            ])
        hosts = sorted({h.host for h in hits})
        return f"hunted {len(targets)} IOCs: {len(hits)} hits on {len(hosts)} hosts"


def _merge_source_entities(iocs: list[IOC], state: InvestigationState) -> list[IOC]:
    """Fold entities the SIEM already extracted into the discovered IOC set."""
    have = {i.key() for i in iocs}
    alert = state.alert
    for ip in alert.src_ips + alert.dst_ips:
        for c in extract_iocs(ip):
            if c.key() not in have:
                iocs.append(c)
                have.add(c.key())
    for user in alert.users:
        if "@" in user:
            key = f"{IOCType.EMAIL.value}:{user.lower()}"
            if key not in have:
                iocs.append(IOC(type=IOCType.EMAIL, value=user.lower()))
                have.add(key)
    return iocs
