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


class PostgresRuleStore:
    """Durable tenant rules (RLS-isolated); same interface as RuleStore."""

    def upsert(self, tenant: str, rule: DetectionRule) -> DetectionRule:
        if rule.id in _BUILTIN_IDS:
            raise ValueError(f"rule id {rule.id} collides with a built-in rule")
        from app.core.tenancy import set_current_tenant
        from app.db.models import DetectionRuleRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rec = (
                session.query(DetectionRuleRecord)
                .filter(DetectionRuleRecord.tenant_id == tenant,
                        DetectionRuleRecord.rule_id == rule.id)
                .one_or_none()
            )
            if rec is None:
                count = (
                    session.query(DetectionRuleRecord)
                    .filter(DetectionRuleRecord.tenant_id == tenant)
                    .count()
                )
                if count >= _MAX_RULES_PER_TENANT:
                    raise ValueError("tenant custom-rule quota exceeded")
                session.add(DetectionRuleRecord(
                    tenant_id=tenant, rule_id=rule.id,
                    rule=rule.model_dump(mode="json")))
            else:
                rec.rule = rule.model_dump(mode="json")
        return rule

    def delete(self, tenant: str, rule_id: str) -> bool:
        from app.core.tenancy import set_current_tenant
        from app.db.models import DetectionRuleRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            deleted = (
                session.query(DetectionRuleRecord)
                .filter(DetectionRuleRecord.tenant_id == tenant,
                        DetectionRuleRecord.rule_id == rule_id)
                .delete()
            )
            return deleted > 0

    def list(self, tenant: str) -> list[DetectionRule]:
        from app.core.tenancy import set_current_tenant
        from app.db.models import DetectionRuleRecord
        from app.db.session import tenant_session

        set_current_tenant(tenant)
        with tenant_session() as session:
            rows = (
                session.query(DetectionRuleRecord)
                .filter(DetectionRuleRecord.tenant_id == tenant)
                .all()
            )
            rules = [DetectionRule.model_validate(r.rule) for r in rows]
        rules.sort(key=lambda r: r.id)
        return rules


_store: RuleStore | PostgresRuleStore | None = None


def build_rule_store() -> RuleStore | PostgresRuleStore:
    global _store
    if _store is None:
        from app.core.config import settings

        _store = PostgresRuleStore() if settings.use_postgres else RuleStore()
    return _store
