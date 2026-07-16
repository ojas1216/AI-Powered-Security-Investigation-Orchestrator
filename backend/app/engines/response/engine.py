"""Response engine: ranked, atomic response actions with impact + rollback.

From the investigation's evidence (malicious IOCs, affected hosts/users, email,
business impact) it generates concrete response actions — block IP/domain/hash,
quarantine device, reset credentials/disable account, purge phishing email,
notify legal/compliance — each with an estimated risk reduction, business and
operational impact, implementation difficulty, and a rollback strategy. Actions
are ranked by risk reduction per unit of difficulty.

This is the granular, decision-support complement to the phase-based
`engines/playbook` (which produces the approval-gated containment steps); the
response engine never auto-executes — disruptive actions carry
`requires_approval=True` and flow through the existing approval workflow.
"""
from __future__ import annotations

from app.schemas.common import IOCType, Severity, Verdict
from app.schemas.investigation import (
    InvestigationPackage,
    ResponseAction,
    ResponsePlan,
)

_DIFF_RANK = {"low": 0, "medium": 1, "high": 2}
_NET_TYPES = {IOCType.IPV4, IOCType.IPV6}
_DOMAIN_TYPES = {IOCType.DOMAIN, IOCType.URL}
_HASH_TYPES = {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}


class ResponseEngine:
    def plan(self, pkg: InvestigationPackage) -> ResponsePlan:
        if pkg.overall_verdict in (Verdict.BENIGN, Verdict.UNKNOWN):
            return ResponsePlan(actions=[])

        actions: list[ResponseAction] = []
        malicious = [e for e in pkg.iocs if e.verdict is Verdict.MALICIOUS]

        for e in malicious:
            v = e.ioc.value
            if e.ioc.type in _NET_TYPES:
                actions.append(ResponseAction(
                    action=f"Block IP {v} at the egress firewall", category="network",
                    target=v, risk_reduction=0.7, business_impact="low",
                    operational_impact="low", difficulty="low",
                    rollback="Remove the firewall/proxy deny rule"))
            elif e.ioc.type in _DOMAIN_TYPES:
                actions.append(ResponseAction(
                    action=f"Block {v} at the proxy and DNS", category="network",
                    target=v, risk_reduction=0.7, business_impact="low",
                    operational_impact="low", difficulty="low",
                    rollback="Remove the proxy/DNS block"))
            elif e.ioc.type in _HASH_TYPES:
                actions.append(ResponseAction(
                    action=f"Add hash {v[:16]}… to the EDR blocklist",
                    category="endpoint", target=v, risk_reduction=0.55,
                    business_impact="low", operational_impact="low",
                    difficulty="low", rollback="Remove the hash from the blocklist"))

        for host in pkg.affected_hosts:
            actions.append(ResponseAction(
                action=f"Quarantine device {host} (network isolation)",
                category="endpoint", target=host, risk_reduction=0.8,
                business_impact="high", operational_impact="high", difficulty="low",
                rollback="Release the host from EDR network isolation"))

        for user in pkg.affected_users:
            actions.append(ResponseAction(
                action=f"Reset credentials and revoke sessions for {user}",
                category="identity", target=user, risk_reduction=0.55,
                business_impact="medium", operational_impact="medium",
                difficulty="low", rollback="User re-enrolls credentials/MFA"))
            if pkg.overall_verdict is Verdict.MALICIOUS and pkg.affected_hosts:
                actions.append(ResponseAction(
                    action=f"Disable account {user} pending review",
                    category="identity", target=user, risk_reduction=0.6,
                    business_impact="high", operational_impact="high",
                    difficulty="low", rollback="Re-enable the account"))

        if _has_email_artifact(pkg):
            actions.append(ResponseAction(
                action="Purge the phishing email from all recipient mailboxes",
                category="email", target="campaign", risk_reduction=0.6,
                business_impact="low", operational_impact="low", difficulty="medium",
                rollback="Restore from mailbox retention if a false positive"))

        if pkg.business_impact and pkg.business_impact.level in (
                Severity.CRITICAL, Severity.HIGH):
            for team in ("Legal", "Compliance"):
                actions.append(ResponseAction(
                    action=f"Notify {team} of a {pkg.business_impact.level.value} "
                           "impact incident", category="escalation", target=team,
                    risk_reduction=0.1, business_impact="low",
                    operational_impact="low", difficulty="low",
                    rollback="n/a — notification", requires_approval=False))

        # Rank: highest risk reduction first, then easiest to implement.
        actions.sort(key=lambda a: (-a.risk_reduction, _DIFF_RANK[a.difficulty]))
        return ResponsePlan(actions=actions)


def _has_email_artifact(pkg: InvestigationPackage) -> bool:
    return (pkg.alert.extra.get("artifact") == "eml"
            or bool(pkg.alert.extra.get("message_id"))
            or any(ev.kind == "email_artifact" for ev in pkg.evidence))


_engine: ResponseEngine | None = None


def build_response_engine() -> ResponseEngine:
    global _engine
    if _engine is None:
        _engine = ResponseEngine()
    return _engine
