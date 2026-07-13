"""Tenant-scoped custom detection rule store.

Detection engineers author rules via the API; rules are validated by the
DetectionRule model at the boundary and kept per-tenant (never visible across
tenants). Process-local implementation mirrors the platform's swappable-backend
pattern; production persists to Postgres with RLS.
"""
from __future__ import annotations

import threading

from app.engines.detection.builtin import BUILTIN_RULES
from app.engines.detection.rules import DetectionRule

_MAX_RULES_PER_TENANT = 1000
_BUILTIN_IDS = {r.id for r in BUILTIN_RULES}


class RuleStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_tenant: dict[str, dict[str, DetectionRule]] = {}

    def upsert(self, tenant: str, rule: DetectionRule) -> DetectionRule:
        if rule.id in _BUILTIN_IDS:
            raise ValueError(f"rule id {rule.id} collides with a built-in rule")
        with self._lock:
            rules = self._by_tenant.setdefault(tenant, {})
            if rule.id not in rules and len(rules) >= _MAX_RULES_PER_TENANT:
                raise ValueError("tenant custom-rule quota exceeded")
            rules[rule.id] = rule
        return rule

    def delete(self, tenant: str, rule_id: str) -> bool:
        with self._lock:
            return self._by_tenant.get(tenant, {}).pop(rule_id, None) is not None

    def list(self, tenant: str) -> list[DetectionRule]:
        with self._lock:
            return sorted(self._by_tenant.get(tenant, {}).values(),
                          key=lambda r: r.id)


_store: RuleStore | None = None


def build_rule_store() -> RuleStore:
    global _store
    if _store is None:
        _store = RuleStore()
    return _store
