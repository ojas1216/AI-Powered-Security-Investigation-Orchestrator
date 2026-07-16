"""Multi-format detection engineering.

Extends the Sigma/YARA generators (Milestone 5 generation agents) to emit
deployable detections for the major SIEM/EDR/IDS platforms — Suricata, Splunk
SPL, Sentinel KQL, Chronicle YARA-L, Elastic EQL, Wazuh, CrowdStrike Falcon —
all grounded in the investigation's confirmed indicators. Every generated rule
carries the detection-engineering metadata: rationale, supporting evidence, and
estimated precision/recall (so an engineer can triage before deployment).

Deterministic string generation — never LLM-hallucinated detections.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.schemas.common import IOCType, Verdict
from app.schemas.investigation import GeneratedRule, InvestigationPackage


@dataclass
class _Indicators:
    ips: list[str]
    domains: list[str]
    urls: list[str]
    hashes: list[str]
    techniques: list[str]
    title: str

    @property
    def has_network(self) -> bool:
        return bool(self.ips or self.domains or self.urls)

    @property
    def any(self) -> bool:
        return bool(self.ips or self.domains or self.urls or self.hashes)


def _extract(pkg: InvestigationPackage) -> _Indicators:
    mal = [e for e in pkg.iocs if e.verdict is Verdict.MALICIOUS]

    def vals(types: set[IOCType]) -> list[str]:
        return sorted({e.ioc.value for e in mal if e.ioc.type in types})

    return _Indicators(
        ips=vals({IOCType.IPV4, IOCType.IPV6}),
        domains=vals({IOCType.DOMAIN}),
        urls=vals({IOCType.URL}),
        hashes=vals({IOCType.SHA256, IOCType.SHA1, IOCType.MD5}),
        techniques=sorted({t.technique_id for t in pkg.mitre}),
        title=pkg.alert.title or "AegisFlow detection",
    )


def _evidence(ind: _Indicators) -> list[str]:
    return [*ind.ips, *ind.domains, *ind.urls, *ind.hashes]


def _q(values: list[str]) -> str:
    return ", ".join(f'"{v}"' for v in values)


class DetectionExportEngine:
    def generate(self, pkg: InvestigationPackage) -> list[GeneratedRule]:
        ind = _extract(pkg)
        rules: list[GeneratedRule] = []

        # Sigma + YARA reuse the existing generation agents (no duplication).
        from app.agents.specialists import get_agent_bundle

        bundle = get_agent_bundle()
        rules.append(GeneratedRule(
            format="sigma", title=ind.title,
            rule=bundle.sigma_generator.generate(
                title=ind.title, iocs=pkg.iocs, detections=pkg.detections),
            rationale="Behavioral + IOC detection from the investigation's "
                      "malicious indicators and fired rules.",
            evidence=_evidence(ind) + ind.techniques,
            estimated_precision=0.72, estimated_recall=0.68))
        if ind.hashes:
            rules.append(GeneratedRule(
                format="yara", title=ind.title,
                rule=bundle.yara_generator.generate(
                    rule_name=pkg.alert.source_alert_id, hashes=ind.hashes,
                    filenames=[], strings=[]),
                rationale="File-hash detection for the confirmed malicious "
                          "sample(s).",
                evidence=ind.hashes,
                estimated_precision=0.98, estimated_recall=0.22))

        if ind.any:
            rules.append(self._suricata(ind))
            rules.append(self._splunk(ind))
            rules.append(self._kql(ind))
            rules.append(self._yaral(ind))
            rules.append(self._eql(ind))
            rules.append(self._wazuh(ind))
            rules.append(self._falcon(ind))
        return rules

    # ---------------------------------------------------------------- formats

    def _suricata(self, ind: _Indicators) -> GeneratedRule:
        lines: list[str] = []
        sid = 9000000
        for ip in ind.ips:
            lines.append(
                f'alert ip any any -> {ip} any (msg:"AegisFlow C2 IP {ip}"; '
                f"sid:{sid}; rev:1;)")
            sid += 1
        for dom in ind.domains:
            lines.append(
                f'alert dns any any -> any any (msg:"AegisFlow C2 domain {dom}"; '
                f'dns.query; content:"{dom}"; nocase; sid:{sid}; rev:1;)')
            sid += 1
        return GeneratedRule(
            format="suricata", title=ind.title, rule="\n".join(lines),
            rationale="Network IDS signatures for confirmed C2 IPs/domains.",
            evidence=[*ind.ips, *ind.domains],
            estimated_precision=0.9, estimated_recall=0.45)

    def _splunk(self, ind: _Indicators) -> GeneratedRule:
        clauses = []
        if ind.ips:
            clauses.append(f"dest_ip IN ({_q(ind.ips)})")
        if ind.domains:
            clauses.append("(" + " OR ".join(f'url=*{d}*' for d in ind.domains) + ")")
        if ind.hashes:
            clauses.append(f"file_hash IN ({_q(ind.hashes)})")
        where = " OR ".join(clauses) or "1=1"
        rule = (f"index=* ({where})\n"
                "| stats count min(_time) as first max(_time) as last "
                "by host, user, dest_ip, url, file_hash\n"
                "| sort - count")
        return GeneratedRule(
            format="splunk_spl", title=ind.title, rule=rule,
            rationale="Splunk search for any host touching the confirmed IOCs.",
            evidence=_evidence(ind),
            estimated_precision=0.88, estimated_recall=0.5)

    def _kql(self, ind: _Indicators) -> GeneratedRule:
        conds = []
        if ind.ips:
            conds.append(f"DestinationIp in ({_q(ind.ips)})")
        if ind.domains:
            conds.append(f"RemoteUrl has_any ({_q(ind.domains)})")
        if ind.hashes:
            conds.append(f"SHA256 in ({_q(ind.hashes)})")
        where = " or ".join(conds) or "true"
        rule = ("union DeviceNetworkEvents, DeviceFileEvents\n"
                f"| where {where}\n"
                "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
                "RemoteIP, RemoteUrl, SHA256")
        return GeneratedRule(
            format="sentinel_kql", title=ind.title, rule=rule,
            rationale="Microsoft Sentinel/Defender KQL hunting query for the IOCs.",
            evidence=_evidence(ind),
            estimated_precision=0.88, estimated_recall=0.5)

    def _yaral(self, ind: _Indicators) -> GeneratedRule:
        net = [*ind.ips, *ind.domains]
        conds = []
        if net:
            conds.append("$e.principal.ip in %aegis_net or "
                         "$e.target.domain.name in %aegis_net")
        if ind.hashes:
            conds.append("$e.target.file.sha256 in %aegis_hash")
        condition = " or ".join(conds) or "$e"
        rule = (
            "rule aegisflow_ioc_match {\n"
            "  meta:\n    author = \"AegisFlow\"\n"
            f"    description = \"{ind.title}\"\n"
            "  events:\n    $e.metadata.event_type != \"EVENTTYPE_UNSPECIFIED\"\n"
            "  condition:\n"
            f"    {condition}\n"
            "}")
        return GeneratedRule(
            format="chronicle_yaral", title=ind.title, rule=rule,
            rationale="Google SecOps (Chronicle) YARA-L rule for the IOCs.",
            evidence=_evidence(ind),
            estimated_precision=0.85, estimated_recall=0.5)

    def _eql(self, ind: _Indicators) -> GeneratedRule:
        conds = []
        if ind.ips:
            conds.append(f"destination.ip in ({_q(ind.ips)})")
        if ind.domains:
            conds.append(f"url.domain in ({_q(ind.domains)})")
        if ind.hashes:
            conds.append(f"file.hash.sha256 in ({_q(ind.hashes)})")
        where = " or ".join(conds) or "true"
        rule = f"any where {where}"
        return GeneratedRule(
            format="elastic_eql", title=ind.title, rule=rule,
            rationale="Elastic Security EQL query for the confirmed IOCs.",
            evidence=_evidence(ind),
            estimated_precision=0.88, estimated_recall=0.5)

    def _wazuh(self, ind: _Indicators) -> GeneratedRule:
        parts = ["<group name=\"aegisflow,\">"]
        rid = 100200
        for value in [*ind.ips, *ind.domains, *ind.hashes]:
            parts.append(
                f'  <rule id="{rid}" level="12">\n'
                f'    <field name="data">{value}</field>\n'
                f'    <description>AegisFlow IOC match: {value}</description>\n'
                "  </rule>")
            rid += 1
        parts.append("</group>")
        return GeneratedRule(
            format="wazuh", title=ind.title, rule="\n".join(parts),
            rationale="Wazuh XML rules matching the IOCs in log data.",
            evidence=_evidence(ind),
            estimated_precision=0.82, estimated_recall=0.4)

    def _falcon(self, ind: _Indicators) -> GeneratedRule:
        conds = []
        if ind.ips:
            conds.append("(" + " OR ".join(f'RemoteAddressIP4="{ip}"'
                                           for ip in ind.ips) + ")")
        if ind.domains:
            conds.append("(" + " OR ".join(f'DomainName="{d}"'
                                           for d in ind.domains) + ")")
        if ind.hashes:
            conds.append("(" + " OR ".join(f'SHA256HashData="{h}"'
                                           for h in ind.hashes) + ")")
        query = " OR ".join(conds) or "event_simpleName=*"
        rule = f"event_platform=Win {query}\n| table timestamp, ComputerName, UserName"
        return GeneratedRule(
            format="falcon", title=ind.title, rule=rule,
            rationale="CrowdStrike Falcon event-search query for the IOCs.",
            evidence=_evidence(ind),
            estimated_precision=0.9, estimated_recall=0.45)


_engine: DetectionExportEngine | None = None


def build_detection_export_engine() -> DetectionExportEngine:
    global _engine
    if _engine is None:
        _engine = DetectionExportEngine()
    return _engine
