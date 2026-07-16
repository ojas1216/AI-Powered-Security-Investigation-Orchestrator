"""Incident DNA: compute typed fingerprints of an investigation and compare them.

Seven fingerprints characterize an incident from different angles:

- **infrastructure** — network indicators (IPs, domains, URLs)
- **malware**        — file hashes, filenames, mutexes, registry keys
- **ttp**            — ATT&CK technique ids
- **identity**       — affected accounts / email indicators
- **threat**         — verdict + tactics + malware presence (the *shape* of threat)
- **campaign**       — infrastructure ∪ TTP (the correlation key that clusters
                       related incidents)
- **incident**       — composite identity of the whole incident

Each fingerprint carries a stable hash (exact-ish identity) and its feature set
(for overlap similarity). This is a typed, multi-dimensional complement to the
flat IOC/technique overlap in `agents/memory.py` and the text similarity in
`engines/semantic` — it answers "same infrastructure, different malware?" which
those cannot. Deterministic and auditable.
"""
from __future__ import annotations

import hashlib

from app.schemas.common import IOCType, Verdict
from app.schemas.investigation import (
    Fingerprint,
    FingerprintMatch,
    IncidentDNA,
    InvestigationPackage,
)

_INFRA_TYPES = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL}
_MALWARE_TYPES = {IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.FILENAME,
                  IOCType.MUTEX, IOCType.REGISTRY_KEY}
_INTERESTING = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)

# Atomic dimensions used for similarity, with weights (composites are derived).
_SIM_WEIGHTS = {"infrastructure": 0.30, "malware": 0.30, "ttp": 0.25,
                "identity": 0.15}


def _fingerprint(kind: str, features: list[str], label: str) -> Fingerprint:
    feats = sorted(set(features))
    digest = (hashlib.sha256("\n".join(feats).encode()).hexdigest()[:16]
              if feats else "")
    return Fingerprint(kind=kind, hash=digest, features=feats, label=label)


class FingerprintEngine:
    def compute(self, pkg: InvestigationPackage) -> IncidentDNA:
        iocs = pkg.iocs

        def vals(types: set[IOCType]) -> list[str]:
            return [e.ioc.value.lower() for e in iocs
                    if e.ioc.type in types and e.verdict in _INTERESTING]

        infra = vals(_INFRA_TYPES)
        malware = vals(_MALWARE_TYPES)
        ttp = [t.technique_id for t in pkg.mitre]
        tactics = sorted({t.tactic for t in pkg.mitre})
        identity = ([u.lower() for u in pkg.affected_users]
                    + [e.ioc.value.lower() for e in iocs
                       if e.ioc.type is IOCType.EMAIL])

        threat_feats = ([f"verdict:{pkg.overall_verdict.value}"]
                        + [f"tactic:{t}" for t in tactics]
                        + (["malware-present"] if malware else []))
        campaign_feats = list(infra) + [f"ttp:{t}" for t in ttp]
        incident_feats = ([f"infra:{i}" for i in infra]
                          + [f"mw:{m}" for m in malware]
                          + [f"ttp:{t}" for t in ttp]
                          + [f"id:{i}" for i in identity])

        fps = [
            _fingerprint("infrastructure", infra,
                         f"{len(set(infra))} network indicator(s)"),
            _fingerprint("malware", malware,
                         f"{len(set(malware))} malware artifact(s)"),
            _fingerprint("ttp", ttp, f"{len(set(ttp))} ATT&CK technique(s)"),
            _fingerprint("identity", identity,
                         f"{len(set(identity))} affected identit(y/ies)"),
            _fingerprint("threat", threat_feats,
                         f"{pkg.overall_verdict.value} / {len(tactics)} tactic(s)"),
            _fingerprint("campaign", campaign_feats,
                         "infrastructure + TTP correlation key"),
            _fingerprint("incident", incident_feats, "composite incident identity"),
        ]
        return IncidentDNA(investigation_id=pkg.investigation_id, fingerprints=fps)

    def similarity(self, a: IncidentDNA, b: IncidentDNA,
                   ) -> tuple[float, dict[str, float], dict[str, list[str]]]:
        dims: dict[str, float] = {}
        shared: dict[str, list[str]] = {}
        weighted_sum = 0.0
        weight_total = 0.0
        for kind, weight in _SIM_WEIGHTS.items():
            fa = set(a.by_kind(kind).features) if a.by_kind(kind) else set()
            fb = set(b.by_kind(kind).features) if b.by_kind(kind) else set()
            union = fa | fb
            if not union:
                continue  # neither incident has this dimension → not comparable
            inter = fa & fb
            jaccard = len(inter) / len(union)
            dims[kind] = round(jaccard, 3)
            if inter:
                shared[kind] = sorted(inter)
            weighted_sum += weight * jaccard
            weight_total += weight
        overall = round(weighted_sum / weight_total, 4) if weight_total else 0.0
        return overall, dims, shared

    def match(self, current: IncidentDNA, priors: list[tuple[IncidentDNA, str]],
              *, min_similarity: float = 0.15, limit: int = 5,
              ) -> list[FingerprintMatch]:
        """Compare `current` against prior (dna, title) pairs; return the most
        similar, most-similar first."""
        matches: list[FingerprintMatch] = []
        for dna, title in priors:
            if dna.investigation_id == current.investigation_id:
                continue
            overall, dims, shared = self.similarity(current, dna)
            if overall >= min_similarity and shared:
                matches.append(FingerprintMatch(
                    investigation_id=dna.investigation_id, title=title,
                    overall_similarity=overall, dimension_similarity=dims,
                    shared=shared))
        matches.sort(key=lambda m: m.overall_similarity, reverse=True)
        return matches[:limit]


_engine: FingerprintEngine | None = None


def build_fingerprint_engine() -> FingerprintEngine:
    global _engine
    if _engine is None:
        _engine = FingerprintEngine()
    return _engine
