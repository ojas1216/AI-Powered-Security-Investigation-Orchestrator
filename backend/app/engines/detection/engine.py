"""Detection engine: evaluate every enabled rule against a normalized alert.

Rules are isolated: one rule raising can never suppress another rule's match or
break ingestion (the failure is logged and counted). Matches report exactly which
fields/matchers fired so a detection engineer can debug a rule from the API alone.
"""
from __future__ import annotations

from app.core.logging import get_logger
from app.engines.detection.rules import (
    DetectionRule,
    FieldMatcher,
    flatten_alert,
)
from app.schemas.alert import Alert
from app.schemas.common import Severity
from app.schemas.investigation import DetectionMatch, MitreTechnique

log = get_logger("detection.engine")

_EXCERPT_LEN = 160


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self._rules: dict[str, DetectionRule] = {}
        for rule in rules or []:
            self.register(rule)

    def register(self, rule: DetectionRule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate detection rule id: {rule.id}")
        self._rules[rule.id] = rule

    def rules(self) -> list[DetectionRule]:
        return sorted(self._rules.values(), key=lambda r: r.id)

    def evaluate(self, alert: Alert, extra_rules: list[DetectionRule] | None = None,
                 ) -> list[DetectionMatch]:
        fields = flatten_alert(alert)
        matches: list[DetectionMatch] = []
        for rule in [*self._rules.values(), *(extra_rules or [])]:
            if not rule.enabled:
                continue
            try:
                hit = self._evaluate_rule(rule, fields)
            except Exception as exc:  # noqa: BLE001 - rule isolation is the contract
                log.error("rule_evaluation_failed", rule_id=rule.id, error=str(exc))
                continue
            if hit is not None:
                matches.append(hit)
        matches.sort(key=lambda m: (_SEV_ORDER[m.severity], m.rule_id))
        return matches

    def _evaluate_rule(self, rule: DetectionRule, fields: dict[str, str],
                       ) -> DetectionMatch | None:
        matched: dict[str, str] = {}

        def check(matcher: FieldMatcher) -> bool:
            value = fields.get(matcher.field, "")
            if value and matcher.matches(value):
                matched.setdefault(matcher.field, value[:_EXCERPT_LEN])
                return True
            return False

        if not all(check(m) for m in rule.condition.all):
            return None
        if rule.condition.any and not any(check(m) for m in rule.condition.any):
            return None
        # NOT-clause: evaluated without polluting matched-field evidence.
        for matcher in rule.condition.none:
            value = fields.get(matcher.field, "")
            if value and matcher.matches(value):
                return None

        return DetectionMatch(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            techniques=[
                MitreTechnique(technique_id=t.technique_id, name=t.name, tactic=t.tactic)
                for t in rule.techniques
            ],
            matched_fields=matched,
            tags=list(rule.tags),
        )


_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
