"""Generation & higher-order analytic agents.

Deliberately **deterministic and grounded** — Sigma/YARA rules and impact/
root-cause analyses are derived from the case's own evidence, never hallucinated
by an LLM (an LLM-invented detection rule is a liability, not an asset). Each is
a SpecialistAgent: independently callable via the /agents API and, for the two
case-level analytics, wired into the investigation package at finalize.

Agents: sigma_generator, yara_generator, root_cause, attack_path, business_impact.
"""
from __future__ import annotations

from app.agents.specialists.base import AgentResult, SpecialistAgent
from app.engines.graph.client import GraphClient
from app.schemas.common import IOCType, Severity, Verdict
from app.schemas.investigation import (
    BusinessImpact,
    DetectionMatch,
    MitreTechnique,
    RootCause,
    TimelineEvent,
)
from app.schemas.ioc import EnrichedIOC

# ATT&CK tactic ordering (kill-chain), earliest first — used to find the root.
_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
_TACTIC_RANK = {t: i for i, t in enumerate(_TACTIC_ORDER)}


# ---------------------------------------------------------------- Sigma


class SigmaGeneratorAgent(SpecialistAgent):
    name = "sigma_generator"
    description = "Generate a valid Sigma detection rule grounded in a case's IOCs/detections"
    input_hint = {"title": "rule title", "iocs": "enriched IOCs or values",
                  "detections": "fired DetectionMatch objects"}

    def generate(self, *, title: str, iocs: list[EnrichedIOC],
                 detections: list[DetectionMatch]) -> str:
        malicious = [e for e in iocs if e.verdict is Verdict.MALICIOUS]
        domains = [e.ioc.value for e in malicious
                   if e.ioc.type in (IOCType.DOMAIN, IOCType.URL)]
        ips = [e.ioc.value for e in malicious
               if e.ioc.type in (IOCType.IPV4, IOCType.IPV6)]
        hashes = [e.ioc.value for e in malicious
                  if e.ioc.type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5)]
        tags = sorted({t.technique_id.lower()
                       for d in detections for t in d.techniques})

        lines = [
            f"title: {title or 'AegisFlow generated detection'}",
            "status: experimental",
            "description: Auto-generated from an AegisFlow investigation; review "
            "before deploying.",
            "logsource:",
            "    category: proxy",
            "detection:",
        ]
        selectors: list[str] = []
        if domains:
            lines.append("    sel_domain:")
            lines.append("        c-uri|contains:")
            lines += [f"            - '{d}'" for d in domains]
            selectors.append("sel_domain")
        if ips:
            lines.append("    sel_ip:")
            lines.append("        dst_ip:")
            lines += [f"            - '{ip}'" for ip in ips]
            selectors.append("sel_ip")
        if hashes:
            lines.append("    sel_hash:")
            lines.append("        Hashes|contains:")
            lines += [f"            - '{h}'" for h in hashes]
            selectors.append("sel_hash")
        if not selectors:
            lines.append("    selection:")
            lines.append("        EventID: 1")
            selectors.append("selection")
        lines.append(f"    condition: {' or '.join(selectors)}")
        if tags:
            lines.append("tags:")
            lines += [f"    - attack.{t}" for t in tags]
        lines.append("level: high")
        return "\n".join(lines)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        iocs = [EnrichedIOC.model_validate(e) for e in payload.get("iocs", []) or []]
        dets = [DetectionMatch.model_validate(d)
                for d in payload.get("detections", []) or []]
        sigma = self.generate(title=str(payload.get("title", "")),
                              iocs=iocs, detections=dets)
        return AgentResult(agent=self.name, summary="sigma rule generated",
                           data={"sigma": sigma})


# ---------------------------------------------------------------- YARA


class YaraGeneratorAgent(SpecialistAgent):
    name = "yara_generator"
    description = "Generate a YARA rule from file hashes, filenames and strings"
    input_hint = {"rule_name": "identifier", "hashes": "list", "filenames": "list",
                  "strings": "list of literal strings to match"}

    def generate(self, *, rule_name: str, hashes: list[str],
                 filenames: list[str], strings: list[str]) -> str:
        ident = _yara_ident(rule_name or "AegisFlow_Generated")
        lines = [f"rule {ident}", "{", "    meta:",
                 '        author = "AegisFlow"',
                 '        description = "Auto-generated; review before use"']
        for i, h in enumerate(hashes):
            lines.append(f'        hash{i} = "{h}"')
        lines.append("    strings:")
        has_string = False
        for i, fn in enumerate(filenames):
            lines.append(f'        $fn{i} = "{_yara_escape(fn)}" nocase')
            has_string = True
        for i, s in enumerate(strings):
            lines.append(f'        $s{i} = "{_yara_escape(s)}"')
            has_string = True
        if not has_string:
            lines.append('        $a = "AEGISFLOW_PLACEHOLDER"')
        lines.append("    condition:")
        lines.append("        any of them")
        lines.append("}")
        return "\n".join(lines)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        yara = self.generate(
            rule_name=str(payload.get("rule_name", "")),
            hashes=[str(h) for h in payload.get("hashes", []) or []],
            filenames=[str(f) for f in payload.get("filenames", []) or []],
            strings=[str(s) for s in payload.get("strings", []) or []],
        )
        return AgentResult(agent=self.name, summary="yara rule generated",
                           data={"yara": yara})


# ---------------------------------------------------------------- Root cause


class RootCauseAgent(SpecialistAgent):
    name = "root_cause"
    description = "Reconstruct the initial vector and kill-chain from timeline + ATT&CK"
    input_hint = {"timeline": "list of TimelineEvent", "mitre": "list of techniques"}

    def analyze(self, timeline: list[TimelineEvent],
                mitre: list[MitreTechnique]) -> RootCause:
        # Order observed tactics along the kill chain.
        tactics = sorted({t.tactic for t in mitre},
                         key=lambda t: _TACTIC_RANK.get(t, len(_TACTIC_ORDER)))
        earliest_tactic = tactics[0] if tactics else None
        initial_tech = next(
            (t for t in mitre if t.tactic == earliest_tactic), None)
        initial_vector = (f"{initial_tech.name} ({initial_tech.technique_id})"
                          if initial_tech else "undetermined")
        # The earliest timeline event is the concrete first observation.
        initial_event = min(timeline, key=lambda e: e.timestamp) if timeline else None
        chain = " → ".join(tactics) if tactics else "no ATT&CK tactics observed"
        first = (f"first observed activity: {initial_event.action}"
                 if initial_event else "no timeline events")
        narrative = (f"Investigation most likely began via {initial_vector}; "
                     f"{first}. Kill chain: {chain}.")
        return RootCause(initial_vector=initial_vector, initial_event=initial_event,
                         kill_chain=tactics, narrative=narrative)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        timeline = [TimelineEvent.model_validate(e)
                    for e in payload.get("timeline", []) or []]
        mitre = [MitreTechnique.model_validate(t)
                 for t in payload.get("mitre", []) or []]
        rc = self.analyze(timeline, mitre)
        return AgentResult(agent=self.name, summary=rc.initial_vector,
                           data={"root_cause": rc.model_dump(mode="json")})


# ---------------------------------------------------------------- Attack path


class AttackPathAgent(SpecialistAgent):
    name = "attack_path"
    description = "Reconstruct the graph path between two entities (attack-path recon)"
    input_hint = {"src": "entity key e.g. host:WS-1", "dst": "entity key",
                  "max_depth": "1..6"}

    def __init__(self, graph: GraphClient) -> None:
        self._graph = graph

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        src = payload.get("src")
        dst = payload.get("dst")
        if not src or not dst:
            return AgentResult(agent=self.name, ok=False,
                               summary="provide 'src' and 'dst' entity keys")
        edges = self._graph.path(tenant, str(src), str(dst),
                                 max_depth=int(payload.get("max_depth", 6)))
        if not edges:
            return AgentResult(agent=self.name, ok=False,
                               summary=f"no path from {src} to {dst}")
        hops = " → ".join([edges[0].src, *[e.dst for e in edges]])
        return AgentResult(
            agent=self.name, summary=f"{len(edges)}-hop path: {hops}",
            data={"path": [e.__dict__ for e in edges], "hops": hops})


# ---------------------------------------------------------------- Business impact


class BusinessImpactAgent(SpecialistAgent):
    name = "business_impact"
    description = "Estimate blast radius, asset classes, cost band and downtime risk"
    input_hint = {"affected_hosts": "list", "affected_users": "list",
                  "verdict": "malicious|suspicious|...", "risk_score": "0..100"}

    def analyze(self, *, affected_hosts: list[str], affected_users: list[str],
                verdict: Verdict, risk_score: float) -> BusinessImpact:
        hosts, users = len(affected_hosts), len(affected_users)
        classes = _asset_classes(affected_hosts)
        crown = any(c in classes for c in ("finance", "domain-controller", "server"))

        # Level: driven by verdict, blast radius and crown-jewel involvement.
        if verdict is Verdict.MALICIOUS and (crown or hosts >= 10 or risk_score >= 85):
            level = Severity.CRITICAL
        elif verdict is Verdict.MALICIOUS:
            level = Severity.HIGH
        elif verdict is Verdict.SUSPICIOUS:
            level = Severity.MEDIUM
        else:
            level = Severity.LOW

        cost = {
            Severity.CRITICAL: "$100k-$1M+",
            Severity.HIGH: "$10k-$100k",
            Severity.MEDIUM: "$1k-$10k",
            Severity.LOW: "<$1k",
        }[level]
        downtime = {
            Severity.CRITICAL: "hours-days (containment likely disrupts operations)",
            Severity.HIGH: "hours (host isolation)",
            Severity.MEDIUM: "minimal",
            Severity.LOW: "none",
        }[level]
        rationale = [
            f"{hosts} host(s) and {users} user(s) in scope",
            f"asset classes: {', '.join(classes) or 'workstation'}",
            f"verdict {verdict.value}, risk {risk_score:.0f}/100",
        ]
        if crown:
            rationale.append("crown-jewel / high-value assets involved")
        return BusinessImpact(
            level=level, blast_radius_hosts=hosts, blast_radius_users=users,
            affected_asset_classes=classes or ["workstation"],
            estimated_cost_band=cost, downtime_risk=downtime, rationale=rationale)

    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        impact = self.analyze(
            affected_hosts=[str(h) for h in payload.get("affected_hosts", []) or []],
            affected_users=[str(u) for u in payload.get("affected_users", []) or []],
            verdict=Verdict(payload.get("verdict", "unknown")),
            risk_score=float(payload.get("risk_score", 0.0)),
        )
        return AgentResult(agent=self.name, summary=f"impact {impact.level.value}",
                           data={"business_impact": impact.model_dump(mode="json")})


# ---------------------------------------------------------------- helpers


def _asset_classes(hosts: list[str]) -> list[str]:
    classes: set[str] = set()
    for h in hosts:
        u = h.upper()
        if "FIN" in u:
            classes.add("finance")
        if u.startswith("DC") or "DC-" in u or "DOMAIN" in u:
            classes.add("domain-controller")
        if "SRV" in u or "SERVER" in u or u.startswith("SQL"):
            classes.add("server")
        if "WS" in u or "LAPTOP" in u or "DESK" in u:
            classes.add("workstation")
    return sorted(classes)


def _yara_ident(name: str) -> str:
    ident = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
    if ident and ident[0].isdigit():
        ident = "r_" + ident
    return ident or "AegisFlow_Generated"


def _yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')
