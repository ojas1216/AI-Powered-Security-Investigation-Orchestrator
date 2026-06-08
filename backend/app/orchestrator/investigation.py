"""The Investigation Orchestrator.

Composes every engine into a single investigation package. This module is
transport-agnostic: it runs in-process for dev/tests, and the same method calls
are wrapped as Temporal activities in `temporal_workflow.py` for durable
production execution.

Flow: extract IOCs → enrich (TI) → email context → detonate attachments → hunt in
EDR → build evidence/timeline/graph → MITRE map → risk score → copilot report →
playbook → ticket.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.engines.copilot import build_copilot
from app.engines.edr import build_edr
from app.engines.email_investigation import build_email
from app.engines.evidence import build_evidence_store
from app.engines.graph import build_graph
from app.engines.graph.client import GraphTriple
from app.engines.ioc_extraction import extract_iocs
from app.engines.mitre import map_techniques
from app.engines.playbook import recommend_playbook
from app.engines.risk_scoring import score_investigation
from app.engines.risk_scoring.scorer import RiskInputs
from app.engines.sandbox import build_sandbox
from app.engines.threat_intel import build_aggregator
from app.engines.ticketing import build_ticketing
from app.engines.timeline import build_timeline
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus, Verdict
from app.schemas.investigation import (
    Evidence,
    InvestigationPackage,
    TimelineEvent,
)
from app.schemas.ioc import EnrichedIOC, IOC

log = get_logger("orchestrator")


class InvestigationOrchestrator:
    def __init__(self) -> None:
        self.ti = build_aggregator()
        self.sandbox = build_sandbox()
        self.edr = build_edr()
        self.email = build_email()
        self.graph = build_graph()
        self.ticketing = build_ticketing()
        self.copilot = build_copilot()
        self.evidence = build_evidence_store()

    async def investigate(self, tenant: str, alert: Alert) -> InvestigationPackage:
        inv_id = str(uuid.uuid4())
        log.info("investigation_start", investigation_id=inv_id, tenant=tenant,
                 alert=alert.source_alert_id)
        pkg = InvestigationPackage(
            investigation_id=inv_id, tenant=tenant,
            status=InvestigationStatus.RUNNING, alert=alert,
        )
        evidence: list[Evidence] = []
        timeline_groups: list[list[TimelineEvent]] = []
        signals: list[str] = [alert.raw_text, alert.title, alert.description]

        # 1. Collect text from the alert and (for phishing) the email body.
        text_corpus = "\n".join([alert.raw_text, alert.title, alert.description])
        email_msg = None
        if "phish" in (alert.title + alert.description).lower() or alert.extra.get("message_id"):
            msg_id = str(alert.extra.get("message_id", alert.source_alert_id))
            email_msg = await self.email.get_message(msg_id)
            text_corpus += "\n" + email_msg.body + "\n" + "\n".join(email_msg.urls)
            recipients = await self.email.find_recipients(msg_id)
            pkg.affected_users = sorted(set(recipients) | set(alert.users))
            timeline_groups.append([
                TimelineEvent(timestamp=email_msg.received_at, actor=email_msg.sender,
                              action="Email delivered", detail=email_msg.subject,
                              source="email")
            ])
            evidence.append(self.evidence.put_json(
                tenant, "email_artifact", "original_email", email_msg.model_dump()))

        # 2. Extract IOCs from everything we gathered + source-provided entities.
        iocs = extract_iocs(text_corpus)
        iocs = _merge_source_entities(iocs, alert)

        # 3. Enrich via threat intel (concurrent, deterministic offline).
        enriched: list[EnrichedIOC] = await self.ti.enrich_many(iocs)
        pkg.iocs = enriched
        for e in enriched:
            if e.verdict is not Verdict.UNKNOWN:
                evidence.append(self.evidence.put_json(
                    tenant, "ti_result", f"ti:{e.ioc.value}", e.model_dump()))

        malicious_iocs = [e for e in enriched if e.verdict is Verdict.MALICIOUS]

        # 4. Detonate attachments (phishing path).
        sandbox_malscore = 0.0
        if email_msg and email_msg.attachments:
            for att in email_msg.attachments:
                report = await self.sandbox.detonate(filename=att.filename)
                sandbox_malscore = max(sandbox_malscore, report.malscore)
                signals.extend(report.signatures)
                signals.extend(report.persistence)
                # fold sandbox-dropped IOCs back into enrichment
                if report.dropped_iocs:
                    dropped = await self.ti.enrich_many(report.dropped_iocs)
                    pkg.iocs.extend(dropped)
                    malicious_iocs.extend(
                        e for e in dropped if e.verdict is Verdict.MALICIOUS)
                evidence.append(self.evidence.put_json(
                    tenant, "sandbox_report", att.filename, report.model_dump()))
                if report.malscore > 0.5:
                    timeline_groups.append([
                        TimelineEvent(timestamp=datetime.now(timezone.utc),
                                      action="Attachment detonated: malicious",
                                      detail=att.filename, source="sandbox")
                    ])

        # 5. Hunt the malicious IOCs in EDR telemetry.
        hunt_iocs = [e.ioc for e in malicious_iocs] or [e.ioc for e in enriched]
        edr_hits = await self.edr.hunt(hunt_iocs)
        pkg.affected_hosts = sorted({h.host for h in edr_hits})
        if edr_hits:
            evidence.append(self.evidence.put_json(
                tenant, "edr_telemetry", "edr_hits",
                [h.model_dump() for h in edr_hits]))
            timeline_groups.append([
                TimelineEvent(timestamp=h.observed_at, actor=h.user,
                              action="IOC observed on host", detail=f"{h.host}: {h.ioc.value}",
                              source="edr")
                for h in edr_hits
            ])

        # 6. Timeline + graph.
        pkg.timeline = build_timeline(*timeline_groups)
        pkg.evidence = evidence
        self._write_graph(tenant, alert, pkg)

        # 7. MITRE mapping.
        has_mal_url = any(
            e.ioc.type.value == "url" and e.verdict is Verdict.MALICIOUS for e in pkg.iocs
        )
        pkg.mitre = map_techniques(signals, has_malicious_url=has_mal_url)

        # 8. Risk scoring.
        pkg.risk = score_investigation(RiskInputs(
            enriched_iocs=pkg.iocs,
            sandbox_malscore=sandbox_malscore,
            edr_confirmed_hits=len(edr_hits),
            mitre=pkg.mitre,
            asset_criticality=_asset_criticality(pkg.affected_hosts),
            recipient_count=len(pkg.affected_users),
        ))
        pkg.overall_verdict = _overall_verdict(pkg.iocs, pkg.risk.score)

        # 9. Copilot narrative (guarded, grounded).
        pkg.executive_summary = await self.copilot.executive_summary(pkg)
        pkg.analyst_report = await self.copilot.analyst_report(pkg)

        # 10. Playbook.
        pkg.playbook = recommend_playbook(pkg.mitre, pkg.overall_verdict)

        # 11. Ticket (only for actionable verdicts).
        if pkg.overall_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            ticket = await self.ticketing.create_ticket(pkg)
            pkg.tickets = [ticket]

        pkg.status = InvestigationStatus.COMPLETE
        pkg.completed_at = datetime.now(timezone.utc)
        log.info("investigation_complete", investigation_id=inv_id,
                 verdict=pkg.overall_verdict.value,
                 risk=pkg.risk.score if pkg.risk else None)
        return pkg

    def _write_graph(self, tenant: str, alert: Alert, pkg: InvestigationPackage) -> None:
        triples: list[GraphTriple] = []
        alert_node = f"alert:{alert.source_alert_id}"
        for e in pkg.iocs:
            triples.append(GraphTriple(alert_node, "contains", e.ioc.key()))
        for host in pkg.affected_hosts:
            triples.append(GraphTriple(f"host:{host}", "affected_by", alert_node))
        for user in pkg.affected_users:
            triples.append(GraphTriple(f"user:{user}", "received", alert_node))
        if triples:
            self.graph.upsert(tenant, triples)


def _merge_source_entities(iocs: list[IOC], alert: Alert) -> list[IOC]:
    from app.schemas.common import IOCType

    have = {i.key() for i in iocs}
    for ip in alert.src_ips + alert.dst_ips:
        candidate = extract_iocs(ip)
        for c in candidate:
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


def _overall_verdict(iocs: list[EnrichedIOC], risk_score: float) -> Verdict:
    if any(e.verdict is Verdict.MALICIOUS for e in iocs) or risk_score >= 70:
        return Verdict.MALICIOUS
    if any(e.verdict is Verdict.SUSPICIOUS for e in iocs) or risk_score >= 35:
        return Verdict.SUSPICIOUS
    if iocs:
        return Verdict.BENIGN
    return Verdict.UNKNOWN


def _asset_criticality(hosts: list[str]) -> float:
    # Hosts in the finance segment are treated as high-criticality (demo heuristic;
    # production reads from a CMDB/asset inventory).
    if any("FIN" in h.upper() for h in hosts):
        return 0.9
    return 0.5 if hosts else 0.3


_orchestrator: InvestigationOrchestrator | None = None


async def run_investigation(tenant: str, alert: Alert) -> InvestigationPackage:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = InvestigationOrchestrator()
    return await _orchestrator.investigate(tenant, alert)
