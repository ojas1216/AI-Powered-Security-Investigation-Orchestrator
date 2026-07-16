"""Campaign detection: cluster incidents that share attacker DNA.

Reuses Incident DNA fingerprints (Milestone 4) and their per-dimension
similarity: two incidents are linked when their fingerprints overlap above a
threshold; connected components of that graph are campaigns. Each cluster
aggregates the shared infrastructure / TTP / malware, the victim set, a time
window, and a threat-actor-type attribution. Deterministic and auditable.

Operates over persisted investigation packages (which carry incident_dna,
timestamps, victims and verdict) — not a new store.
"""
from __future__ import annotations

import hashlib

from app.engines.campaign.attribution import build_attribution_engine
from app.engines.fingerprint import build_fingerprint_engine
from app.schemas.common import Verdict
from app.schemas.investigation import (
    Attribution,
    CampaignCluster,
    InvestigationPackage,
)

_LINK_THRESHOLD = 0.30  # fingerprint overall-similarity to link two incidents
_ACTIONABLE = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self._parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        self._parent[self.find(a)] = self.find(b)


class CampaignEngine:
    def __init__(self) -> None:
        self._fp = build_fingerprint_engine()
        self._attr = build_attribution_engine()

    def cluster(self, packages: list[InvestigationPackage]) -> list[CampaignCluster]:
        actionable = [p for p in packages
                      if p.incident_dna is not None
                      and p.overall_verdict in _ACTIONABLE]
        if not actionable:
            return []

        by_id = {p.investigation_id: p for p in actionable}
        uf = _UnionFind(list(by_id))

        # Link incidents whose fingerprints overlap above the threshold.
        ids = list(by_id)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = by_id[ids[i]], by_id[ids[j]]
                overall, _dims, _shared = self._fp.similarity(
                    a.incident_dna, b.incident_dna)
                if overall >= _LINK_THRESHOLD:
                    uf.union(ids[i], ids[j])

        groups: dict[str, list[InvestigationPackage]] = {}
        for inv_id, pkg in by_id.items():
            groups.setdefault(uf.find(inv_id), []).append(pkg)

        clusters = [self._build_cluster(members) for members in groups.values()
                    if len(members) >= 2]  # a campaign needs >= 2 incidents
        clusters.sort(key=lambda c: c.size, reverse=True)
        return clusters

    def cluster_for(self, investigation_id: str,
                    packages: list[InvestigationPackage]) -> CampaignCluster | None:
        for cluster in self.cluster(packages):
            if investigation_id in cluster.members:
                return cluster
        return None

    def _build_cluster(self, members: list[InvestigationPackage]) -> CampaignCluster:
        member_ids = sorted(p.investigation_id for p in members)
        campaign_id = "camp:" + hashlib.sha256(
            "\n".join(member_ids).encode()).hexdigest()[:12]

        def feats(kind: str) -> list[str]:
            sets = [set(p.incident_dna.by_kind(kind).features)
                    for p in members if p.incident_dna.by_kind(kind)]
            if not sets:
                return []
            # Features present in >= 2 members are the campaign's shared signature.
            counts: dict[str, int] = {}
            for s in sets:
                for f in s:
                    counts[f] = counts.get(f, 0) + 1
            return sorted(f for f, c in counts.items() if c >= 2)

        techniques = sorted({t.technique_id for p in members for t in p.mitre})
        tactics = {t.tactic for p in members for t in p.mitre}
        victims = sorted({u for p in members for u in p.affected_users})
        hosts = {h for p in members for h in p.affected_hosts}
        times = [p.created_at for p in members if p.created_at]
        shared_infra = feats("infrastructure")
        shared_malware = feats("malware")
        worst = (Verdict.MALICIOUS
                 if any(p.overall_verdict is Verdict.MALICIOUS for p in members)
                 else Verdict.SUSPICIOUS)

        attribution: Attribution = self._attr.attribute(
            techniques=set(techniques), tactics=tactics,
            infra_count=len(shared_infra), malware_count=len(shared_malware),
            identity_count=len(victims), host_count=len(hosts))

        return CampaignCluster(
            campaign_id=campaign_id, members=member_ids, size=len(members),
            shared_infrastructure=shared_infra,
            shared_techniques=[t for t in techniques],
            shared_malware=shared_malware, victims=victims,
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
            verdict=worst, attribution=attribution)


_engine: CampaignEngine | None = None


def build_campaign_engine() -> CampaignEngine:
    global _engine
    if _engine is None:
        _engine = CampaignEngine()
    return _engine
