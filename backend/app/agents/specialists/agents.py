"""Concrete specialist agents wrapping the existing engines.

Each agent keeps a typed convenience method (used by the loop's Toolbox, so the
logic lives in exactly one place) plus a generic `run(payload)` for the API.
Nothing here re-implements engine logic — agents are thin, typed adapters.
"""
from __future__ import annotations

from app.agents.memory import CaseMemory
from app.agents.specialists.base import AgentResult, SpecialistAgent
from app.engines.detection import DetectionEngine, RuleStore
from app.engines.detection.engine import DetectionMatch
from app.engines.edr.base import EDRConnector, EDRHit
from app.engines.email_investigation.base import EmailConnector, EmailMessage
from app.engines.ioc_extraction import extract_iocs
from app.engines.mitre import map_techniques
from app.engines.risk_scoring import score_investigation
from app.engines.risk_scoring.scorer import RiskInputs
from app.engines.sandbox.base import SandboxConnector, SandboxReport
from app.engines.threat_intel.aggregator import ThreatIntelAggregator
from app.schemas.alert import Alert
from app.schemas.common import IOCType, Verdict
from app.schemas.investigation import MitreTechnique, RiskBreakdown
from app.schemas.ioc import IOC, EnrichedIOC


def _iocs_from_payload(payload: dict) -> list[IOC]:
    """Accept either free text (`text`) or explicit `indicators`/`iocs`."""
    iocs: list[IOC] = []
    seen: set[str] = set()

    def add(ioc: IOC) -> None:
        if ioc.key() not in seen:
            iocs.append(ioc)
            seen.add(ioc.key())

    if isinstance(payload.get("text"), str):
        for ioc in extract_iocs(payload["text"]):
            add(ioc)
    for raw in payload.get("indicators", []) or []:
        for ioc in extract_iocs(str(raw)):
            add(ioc)
    for raw in payload.get("iocs", []) or []:
        if isinstance(raw, dict) and "type" in raw and "value" in raw:
            add(IOC(type=IOCType(raw["type"]), value=str(raw["value"])))
        else:
            for ioc in extract_iocs(str(raw)):
                add(ioc)
    return iocs


class IocExtractionAgent(SpecialistAgent):
    name = "ioc_extraction"
    description = "Extract fanged/defanged IOCs (IP, domain, url, hash, email) from text"
    input_hint = {"text": "free text to scan for indicators"}

    def extract(self, text: str) -> list[IOC]:
        return extract_iocs(text)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        iocs = self.extract(str(payload.get("text", "")))
        return AgentResult(
            agent=self.name, summary=f"{len(iocs)} indicators extracted",
            data={"iocs": [i.model_dump(mode="json") for i in iocs]})


class ThreatIntelAgent(SpecialistAgent):
    name = "threat_intel"
    description = "Fan out indicators to threat-intel connectors and fuse verdicts"
    input_hint = {"text": "text with IOCs", "indicators": "list of raw indicators"}

    def __init__(self, aggregator: ThreatIntelAggregator) -> None:
        self._agg = aggregator

    async def enrich(self, iocs: list[IOC]) -> list[EnrichedIOC]:
        return await self._agg.enrich_many(iocs)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        iocs = _iocs_from_payload(payload)
        if not iocs:
            return AgentResult(agent=self.name, ok=False,
                               summary="no indicators found in payload")
        enriched = await self.enrich(iocs)
        mal = sum(1 for e in enriched if e.verdict is Verdict.MALICIOUS)
        sus = sum(1 for e in enriched if e.verdict is Verdict.SUSPICIOUS)
        return AgentResult(
            agent=self.name,
            summary=f"enriched {len(enriched)}: {mal} malicious, {sus} suspicious",
            data={"iocs": [e.model_dump(mode="json") for e in enriched]})


class DetectionAgent(SpecialistAgent):
    name = "detection"
    description = "Evaluate built-in + tenant detection rules against an alert"
    input_hint = {"alert": "normalized Alert object", "raw_text": "shorthand: alert text"}

    def __init__(self, engine: DetectionEngine, rule_store: RuleStore) -> None:
        self._engine = engine
        self._store = rule_store

    def evaluate(self, alert: Alert, extra_rules=None) -> list[DetectionMatch]:
        return self._engine.evaluate(alert, extra_rules=extra_rules)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        alert = _alert_from_payload(payload)
        matches = self.evaluate(alert, extra_rules=self._store.list(tenant))
        return AgentResult(
            agent=self.name, summary=f"{len(matches)} rule(s) fired",
            data={"detections": [m.model_dump(mode="json") for m in matches]})


class EdrHuntAgent(SpecialistAgent):
    name = "edr_hunt"
    description = "Hunt indicators across EDR telemetry to confirm on-host activity"
    input_hint = {"text": "text with IOCs", "indicators": "list of raw indicators"}

    def __init__(self, edr: EDRConnector) -> None:
        self._edr = edr

    async def hunt(self, iocs: list[IOC]) -> list[EDRHit]:
        return await self._edr.hunt(iocs)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        iocs = _iocs_from_payload(payload)
        if not iocs:
            return AgentResult(agent=self.name, ok=False, summary="no indicators")
        hits = await self.hunt(iocs)
        hosts = sorted({h.host for h in hits})
        return AgentResult(
            agent=self.name,
            summary=f"{len(hits)} hit(s) on {len(hosts)} host(s)",
            data={"edr_hits": [h.model_dump(mode="json") for h in hits],
                  "affected_hosts": hosts})


class SandboxAgent(SpecialistAgent):
    name = "sandbox"
    description = "Detonate a file/URL in the sandbox and report behavior + dropped IOCs"
    input_hint = {"filename": "attachment filename", "url": "url to detonate"}

    def __init__(self, sandbox: SandboxConnector) -> None:
        self._sandbox = sandbox

    async def detonate(self, *, filename: str | None = None,
                       url: str | None = None) -> SandboxReport:
        return await self._sandbox.detonate(filename=filename or "", url=url)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        filename = payload.get("filename")
        url = payload.get("url")
        if not filename and not url:
            return AgentResult(agent=self.name, ok=False,
                               summary="provide 'filename' or 'url'")
        report = await self.detonate(filename=filename, url=url)
        return AgentResult(
            agent=self.name,
            summary=f"malscore {report.malscore:.2f}, verdict {report.verdict}",
            data={"report": report.model_dump(mode="json")})


class EmailAgent(SpecialistAgent):
    name = "email"
    description = "Fetch a reported email and its campaign recipients"
    input_hint = {"message_id": "mailbox message id"}

    def __init__(self, email: EmailConnector) -> None:
        self._email = email

    async def get_message(self, message_id: str) -> EmailMessage:
        return await self._email.get_message(message_id)

    async def find_recipients(self, message_id: str) -> list[str]:
        return await self._email.find_recipients(message_id)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        msg_id = payload.get("message_id")
        if not msg_id:
            return AgentResult(agent=self.name, ok=False, summary="provide 'message_id'")
        msg = await self.get_message(str(msg_id))
        recipients = await self.find_recipients(str(msg_id))
        return AgentResult(
            agent=self.name,
            summary=f"'{msg.subject}' from {msg.sender}, {len(recipients)} recipients",
            data={"message": msg.model_dump(mode="json"), "recipients": recipients})


class MitreAgent(SpecialistAgent):
    name = "mitre"
    description = "Map observed behaviors/signals to ATT&CK techniques"
    input_hint = {"signals": "list of behavior strings", "text": "free text"}

    def map(self, signals: list[str], *, has_malicious_url: bool = False
            ) -> list[MitreTechnique]:
        return map_techniques(signals, has_malicious_url=has_malicious_url)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        signals = list(payload.get("signals") or [])
        if isinstance(payload.get("text"), str):
            signals.append(payload["text"])
        techs = self.map(signals, has_malicious_url=bool(payload.get("has_malicious_url")))
        return AgentResult(
            agent=self.name, summary=f"{len(techs)} technique(s) mapped",
            data={"techniques": [t.model_dump(mode="json") for t in techs]})


class RiskAgent(SpecialistAgent):
    name = "risk"
    description = "Fuse TI/sandbox/EDR/ATT&CK/asset factors into an explainable 0-100 score"
    input_hint = {"enriched_iocs": "list", "sandbox_malscore": "0..1",
                  "edr_confirmed_hits": "int", "recipient_count": "int"}

    def score(self, inputs: RiskInputs) -> RiskBreakdown:
        return score_investigation(inputs)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        enriched = [EnrichedIOC.model_validate(e)
                    for e in payload.get("enriched_iocs", []) or []]
        techs = [MitreTechnique.model_validate(t)
                 for t in payload.get("mitre", []) or []]
        risk = self.score(RiskInputs(
            enriched_iocs=enriched,
            sandbox_malscore=float(payload.get("sandbox_malscore", 0.0)),
            edr_confirmed_hits=int(payload.get("edr_confirmed_hits", 0)),
            mitre=techs,
            asset_criticality=float(payload.get("asset_criticality", 0.3)),
            recipient_count=int(payload.get("recipient_count", 0)),
        ))
        return AgentResult(
            agent=self.name,
            summary=f"risk {risk.score:.0f} ({risk.severity.value})",
            data={"risk": risk.model_dump(mode="json")})


class MemoryAgent(SpecialistAgent):
    name = "memory"
    description = "Recall tenant-scoped prior investigations similar to given indicators"
    input_hint = {"text": "text with IOCs", "indicators": "list",
                  "technique_ids": "list of ATT&CK ids"}

    def __init__(self, memory: CaseMemory) -> None:
        self._memory = memory

    def recall(self, tenant: str, ioc_keys: set[str], technique_ids: set[str],
               limit: int = 5):
        return self._memory.recall(tenant, ioc_keys, technique_ids, limit=limit)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        ioc_keys = {i.key() for i in _iocs_from_payload(payload)}
        techs = set(payload.get("technique_ids") or [])
        related = self.recall(tenant, ioc_keys, techs)
        return AgentResult(
            agent=self.name, summary=f"{len(related)} related past case(s)",
            data={"related_investigations": [r.model_dump(mode="json") for r in related]})


def _alert_from_payload(payload: dict) -> Alert:
    if isinstance(payload.get("alert"), dict):
        return Alert.model_validate(payload["alert"])
    # Shorthand: build a minimal alert from raw text so ad-hoc rule testing is easy.
    from app.schemas.common import SourceProduct

    return Alert(
        source=SourceProduct.GENERIC,
        source_alert_id=str(payload.get("id", "adhoc")),
        title=str(payload.get("title", "ad-hoc evaluation")),
        description=str(payload.get("description", "")),
        raw_text=str(payload.get("raw_text", payload.get("text", ""))),
    )
