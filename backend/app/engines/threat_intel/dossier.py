"""Dossier engine — assemble a complete threat-intelligence report for one IOC.

Modular pipeline: classify → parallel enrichment (aggregator + ThreatFox, each
failure-isolated) → DNS/WHOIS/hosting → correlate verdicts (confidence) →
MITRE → predicted attack path → threat-actor-type attribution → campaign
correlation (against stored incident DNA) → relationships (+ graph) → business
impact → executive summary. Every step reuses an existing engine; nothing here
re-implements enrichment or scoring. Offline-first and deterministic.
"""
from __future__ import annotations

from app.core.logging import get_logger
from app.engines.threat_intel.aggregator import fuse_verdicts
from app.engines.threat_intel.classifier import classify
from app.engines.threat_intel.domain_intel import build_domain_intel
from app.schemas.common import IOCType, Verdict
from app.schemas.intel import (
    DossierBusinessImpact,
    DossierConfidence,
    DossierTimeline,
    MitreContext,
    ProviderResult,
    Relationships,
    ThreatIntelligenceDossier,
)
from app.schemas.investigation import RootCause
from app.schemas.ioc import IOC, SourceVerdict

log = get_logger("ti.dossier")

_NETWORK = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.CIDR}


class DossierEngine:
    def __init__(self) -> None:
        from app.engines.threat_intel import build_aggregator
        from app.engines.threat_intel.connectors.threatfox import (
            build_threatfox_connector,
        )
        from app.engines.threat_intel.dossier_sources import build_dossier_connectors

        self._aggregator = build_aggregator()
        self._threatfox = build_threatfox_connector()
        self._connectors = build_dossier_connectors()
        self._domain = build_domain_intel()

    async def build(self, indicator: str, tenant: str) -> ThreatIntelligenceDossier:
        ioc = classify(indicator)
        d = ThreatIntelligenceDossier(indicator=ioc.value, ioc_type=ioc.type)

        # --- parallel enrichment (every source failure-isolated) -----------
        import asyncio

        enriched = await self._aggregator.enrich_one(ioc)
        tfox = await self._safe(self._threatfox.enrich(ioc), "threatfox.enrich")
        tfox_verdict = await self._safe(self._threatfox.lookup(ioc), "threatfox.lookup")
        extra = await asyncio.gather(
            *(self._safe(c.enrich(ioc), c.name) for c in self._connectors))

        providers: list[ProviderResult] = [
            ProviderResult(source=s.source, verdict=s.verdict, confidence=s.score,
                           detail=s.detail or "")
            for s in enriched.sources
        ]
        if tfox is not None and tfox_verdict is not None:
            providers.append(ProviderResult(
                source="threatfox", verdict=tfox_verdict.verdict,
                confidence=tfox_verdict.score,
                malware_family=tfox.malware_printable or tfox.malware,
                threat_category=tfox.threat_type, tags=tfox.tags,
                references=tfox.reference, detail=tfox.threat_description))
        providers += [r for r in extra if r is not None]
        d.threat_intel = providers

        # --- fuse verdict + confidence (reuse aggregator fusion) ------------
        all_sources: list[SourceVerdict] = list(enriched.sources)
        if tfox_verdict is not None:
            all_sources.append(tfox_verdict)
        all_sources += [
            SourceVerdict(source=r.source, verdict=r.verdict, score=r.confidence)
            for r in extra if r is not None and r.verdict is not Verdict.UNKNOWN
        ]
        verdict, confidence = fuse_verdicts(all_sources)
        d.verdict = verdict
        d.risk_score = round(confidence * 100, 1)
        d.classification = (tfox.threat_type if tfox else "") or verdict.value
        d.status = _status(verdict, tfox is not None)
        d.confidence = _confidence(providers, verdict, confidence)

        # --- DNS / WHOIS / hosting -----------------------------------------
        if ioc.type in (IOCType.DOMAIN, IOCType.URL):
            d.whois = self._domain.whois(ioc)
            d.dns = self._domain.dns(ioc)
        if ioc.type in _NETWORK:
            d.hosting = self._domain.hosting(ioc)
            d.passive_dns = self._domain.passive_dns(ioc)

        # --- MITRE + predicted path ----------------------------------------
        d.mitre = self._mitre(ioc, tfox, verdict)

        families = sorted({p.malware_family for p in providers if p.malware_family})

        # --- attribution (type only, never a named group) ------------------
        from app.engines.campaign import build_attribution_engine

        d.attribution = build_attribution_engine().attribute(
            techniques={t.technique_id for t in d.mitre.techniques},
            tactics={t.tactic for t in d.mitre.techniques},
            infra_count=1 if ioc.type in _NETWORK else 0,
            malware_count=1 if families else 0,
            identity_count=1 if ioc.type is IOCType.EMAIL else 0, host_count=0)

        # --- campaign correlation against stored incidents -----------------
        d.campaign_matches = _campaign_matches(ioc, tenant)

        # --- relationships (ThreatFox related + campaigns + graph) ---------
        d.relationships = self._relationships(ioc, tfox, tenant, d.campaign_matches)
        for fam in families:
            if fam not in d.relationships.threat_actors:
                d.relationships.threat_actors.append(fam)

        # --- timeline -------------------------------------------------------
        if tfox:
            d.timeline = DossierTimeline(
                first_seen=_dt(tfox.first_seen), last_seen=_dt(tfox.last_seen),
                events=[f"first reported by {tfox.reporter or 'threatfox'}",
                        f"malware: {tfox.malware_printable or tfox.malware or 'n/a'}"])

        # --- business impact + summary + evidence --------------------------
        d.business_impact = _business_impact(ioc, verdict, tfox)
        d.references = _references(providers, tfox)
        d.evidence = _evidence(providers, enriched.sources)
        d.executive_summary = _summary(d, tfox)

        self._write_graph(ioc, tfox, tenant)
        log.info("dossier_built", indicator=ioc.key(), tenant=tenant,
                 verdict=verdict.value, providers=len(providers))
        return d

    @staticmethod
    async def _safe(coro, label: str):
        """Await a provider coroutine; isolate failures so the dossier survives."""
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001 - a provider must never break the dossier
            log.warning("dossier_provider_failed", provider=label, error=str(exc))
            return None

    # ------------------------------------------------------------------ mitre

    def _mitre(self, ioc: IOC, tfox, verdict: Verdict) -> MitreContext:
        from app.engines.mitre import map_techniques
        from app.engines.prediction import build_prediction_engine

        signals: list[str] = []
        if tfox:
            signals += tfox.tags + [tfox.threat_type, tfox.malware]
            if any(k in (tfox.threat_type or "").lower()
                   for k in ("botnet", "c2", "cc")):
                signals.append("http")  # application-layer C2 -> T1071
        techniques = map_techniques(signals, has_malicious_url=(
            ioc.type is IOCType.URL and verdict is Verdict.MALICIOUS))
        tactics = sorted({t.tactic for t in techniques})
        pred = build_prediction_engine().predict(
            RootCause(kill_chain=tactics), techniques, verdict)
        return MitreContext(techniques=techniques, kill_chain=tactics,
                            predicted_next=[p.name for p in pred.predictions])

    # ------------------------------------------------------------ relationships

    def _relationships(self, ioc: IOC, tfox, tenant: str,
                       campaign_matches) -> Relationships:
        rel = Relationships()
        if tfox:
            for r in tfox.related:
                rc = classify(r)
                if rc.type in (IOCType.IPV4, IOCType.IPV6):
                    rel.related_ips.append(rc.value)
                elif rc.type is IOCType.DOMAIN:
                    rel.related_domains.append(rc.value)
                elif rc.type is IOCType.URL:
                    rel.related_urls.append(rc.value)
                elif rc.type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
                    rel.related_hashes.append(rc.value)
            if tfox.malware_printable or tfox.malware:
                rel.threat_actors.append(tfox.malware_printable or tfox.malware)
        rel.campaigns = [m.investigation_id for m in campaign_matches]

        # graph neighbours (co-occurring entities from prior investigations)
        from app.engines.graph import build_graph, node_type

        sub = build_graph().neighbors(tenant, ioc.key(), depth=1)
        for node in sub.nodes:
            if node == ioc.key():
                continue
            t = node_type(node)
            val = node.split(":", 1)[-1]
            if t in ("ipv4", "ipv6") and val not in rel.related_ips:
                rel.related_ips.append(val)
            elif t == "domain" and val not in rel.related_domains:
                rel.related_domains.append(val)
        return rel

    def _write_graph(self, ioc: IOC, tfox, tenant: str) -> None:
        from app.engines.graph import build_graph
        from app.engines.graph.client import GraphTriple

        triples = []
        if tfox and (tfox.malware_printable or tfox.malware):
            triples.append(GraphTriple(
                ioc.key(), "attributed_to",
                f"malware:{(tfox.malware_printable or tfox.malware).lower()}"))
        for r in (tfox.related if tfox else []):
            triples.append(GraphTriple(ioc.key(), "related_to", classify(r).key()))
        if triples:
            build_graph().upsert(tenant, triples)


# ---------------------------------------------------------------- helpers


def _status(verdict: Verdict, listed: bool) -> str:
    if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        return "active"
    if verdict is Verdict.BENIGN:
        return "inactive"
    return "active" if listed else "unknown"


def _confidence(providers: list[ProviderResult], verdict: Verdict,
                confidence: float) -> DossierConfidence:
    supporting = [f"{p.source}: {p.verdict.value} ({p.confidence:.0%})"
                  for p in providers if p.verdict is verdict]
    rejected = [f"{p.source}: {p.verdict.value}"
                for p in providers if p.verdict is not verdict
                and p.verdict is not Verdict.UNKNOWN]
    rationale = [f"{len(supporting)} of {len(providers)} source(s) agree on "
                 f"{verdict.value}."]
    if len(supporting) <= 1:
        rationale.append("Conclusion rests on a single source; treat with caution.")
    return DossierConfidence(score=confidence, rationale=rationale,
                             supporting=supporting, rejected=rejected)


def _campaign_matches(ioc: IOC, tenant: str):
    from app.engines.fingerprint import build_fingerprint_store
    from app.schemas.investigation import FingerprintMatch

    matches = []
    key = ioc.value.lower()
    for dna, title in build_fingerprint_store().all_for_tenant(tenant):
        shared: dict[str, list[str]] = {}
        for kind in ("infrastructure", "malware"):
            fp = dna.by_kind(kind)
            if fp and key in {f.lower() for f in fp.features}:
                shared[kind] = [key]
        if shared:
            matches.append(FingerprintMatch(
                investigation_id=dna.investigation_id, title=title,
                overall_similarity=0.6, dimension_similarity={k: 1.0 for k in shared},
                shared=shared))
    return matches[:10]


def _business_impact(ioc: IOC, verdict: Verdict, tfox) -> DossierBusinessImpact:
    if verdict not in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        return DossierBusinessImpact(
            technical_impact="none", business_impact="none",
            potential_data_exposure="none",
            recommended_actions=["No action required; monitor."])
    family = (tfox.malware_printable or tfox.malware) if tfox else ""
    actions = []
    if ioc.type in (IOCType.IPV4, IOCType.IPV6, IOCType.CIDR):
        actions.append(f"Block {ioc.value} at the egress firewall/proxy")
    elif ioc.type in (IOCType.DOMAIN, IOCType.URL):
        actions.append(f"Block {ioc.value} at the proxy and DNS")
    elif ioc.type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
        actions.append(f"Add {ioc.value[:16]}… to the EDR blocklist")
    actions.append("Hunt for the indicator across EDR/SIEM telemetry")
    if family:
        actions.append(f"Deploy {family} detections and check for lateral spread")
    return DossierBusinessImpact(
        technical_impact=f"Confirmed malicious {ioc.type.value}"
                         + (f" tied to {family}" if family else ""),
        business_impact="Potential compromise / C2 exposure if reached from the estate",
        potential_data_exposure="Credential theft / data exfiltration risk"
        if family else "Unauthorized access risk",
        recommended_actions=actions)


def _references(providers: list[ProviderResult], tfox) -> list[str]:
    refs: list[str] = []
    for p in providers:
        refs += p.references
    if tfox:
        refs += tfox.reference
    return sorted(set(refs))


def _evidence(providers: list[ProviderResult],
              sources: list[SourceVerdict]) -> list[str]:
    return [f"{p.source}: {p.verdict.value} @ {p.confidence:.0%}"
            + (f" — {p.detail}" if p.detail else "") for p in providers]


def _summary(d: ThreatIntelligenceDossier, tfox) -> str:
    if d.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        family = (tfox.malware_printable or tfox.malware) if tfox else ""
        head = (f"{d.indicator} is assessed {d.verdict.value.upper()} "
                f"({d.risk_score:.0f}/100 risk)")
        fam = f", associated with {family}" if family else ""
        actor = (f" Likely actor type: {d.attribution.actor_type}."
                 if d.attribution and d.attribution.actor_type != "unattributed"
                 else "")
        camp = (f" Correlates with {len(d.campaign_matches)} prior incident(s)."
                if d.campaign_matches else "")
        return f"{head}{fam}, corroborated by {len(d.threat_intel)} source(s).{actor}{camp}"
    return (f"{d.indicator} shows no malicious corroboration across "
            f"{len(d.threat_intel)} source(s); verdict {d.verdict.value}.")


def _dt(value: str):
    from datetime import datetime

    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


_engine: DossierEngine | None = None


def build_dossier_engine() -> DossierEngine:
    global _engine
    if _engine is None:
        _engine = DossierEngine()
    return _engine
