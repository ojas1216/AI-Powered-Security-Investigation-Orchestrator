"""Concrete offline datasets: ATT&CK techniques, CVE lookup, Sigma rule pack."""
from __future__ import annotations

from pydantic import BaseModel

from app.engines.detection.rules import (
    DetectionRule,
    FieldMatcher,
    Modifier,
    RuleCondition,
    TechniqueRef,
)
from app.engines.offline_cache.base import DatasetCache
from app.schemas.common import Severity


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str


class CveRecord(BaseModel):
    cve_id: str
    cvss: float = 0.0
    severity: str = "unknown"
    summary: str = ""
    references: list[str] = []
    cwe: str = ""


class MitreAttackCache(DatasetCache):
    name = "attack"
    bundled_file = "attack.json"
    source_url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json")

    def _parse(self, raw: dict) -> dict[str, AttackTechnique]:
        return {
            tid: AttackTechnique(technique_id=tid, name=v["name"], tactic=v["tactic"])
            for tid, v in raw.get("techniques", {}).items()
        }

    def count(self) -> int:
        return len(self.data())

    def get(self, technique_id: str) -> AttackTechnique | None:
        return self.data().get(technique_id.upper())

    def all(self) -> list[AttackTechnique]:
        return sorted(self.data().values(), key=lambda t: t.technique_id)


class CveCache(DatasetCache):
    name = "cve"
    bundled_file = "cve.json"
    source_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _parse(self, raw: dict) -> dict[str, CveRecord]:
        return {
            cid: CveRecord(cve_id=cid, **v)
            for cid, v in raw.get("records", {}).items()
        }

    def count(self) -> int:
        return len(self.data())

    def get(self, cve_id: str) -> CveRecord | None:
        return self.data().get(cve_id.upper())

    def all(self) -> list[CveRecord]:
        return sorted(self.data().values(), key=lambda c: c.cve_id)


class SigmaCache(DatasetCache):
    name = "sigma"
    bundled_file = "sigma.json"
    source_url = "https://github.com/SigmaHQ/sigma"

    def _parse(self, raw: dict) -> list[dict]:
        return list(raw.get("rules", []))

    def count(self) -> int:
        return len(self.data())

    def as_detection_rules(self) -> list[DetectionRule]:
        """Convert the Sigma pack into the platform's DetectionRule DSL so an
        analyst can import them into their tenant rule set."""
        rules: list[DetectionRule] = []
        for r in self.data():
            modifier = Modifier(r.get("modifier", "contains"))
            rules.append(DetectionRule(
                id=r["id"],
                title=r["title"],
                description=f"Imported from offline Sigma pack ({r['id']}).",
                severity=Severity(r.get("severity", "medium")),
                condition=RuleCondition(all=(FieldMatcher(
                    field=r.get("field", "text"), modifier=modifier,
                    values=tuple(r["values"])),)),
                techniques=(TechniqueRef(
                    technique_id=r["technique_id"], name=r["technique_name"],
                    tactic=r["tactic"]),),
                tags=tuple(r.get("tags", ())),
                references=("https://github.com/SigmaHQ/sigma",),
            ))
        return rules
