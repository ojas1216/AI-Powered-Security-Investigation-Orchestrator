"""Authorization: RBAC + ABAC.

RBAC maps roles → permissions. ABAC layers attribute predicates (tenant match,
asset sensitivity, ownership) on top, so the right role is necessary but not always
sufficient. Every endpoint declares the permission it needs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.core.exceptions import ForbiddenError
from app.core.security import Principal


class Role(StrEnum):
    SUPER_ADMIN = "super_admin"
    SOC_MANAGER = "soc_manager"
    TIER1 = "tier1_analyst"
    TIER2 = "tier2_analyst"
    TIER3 = "tier3_analyst"
    THREAT_HUNTER = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"
    AUDITOR = "auditor"


class Permission(StrEnum):
    ALERT_INGEST = "alert:ingest"
    INVESTIGATION_READ = "investigation:read"
    INVESTIGATION_CREATE = "investigation:create"
    INVESTIGATION_ACT = "investigation:act"  # containment/eradication actions
    IOC_READ = "ioc:read"
    COPILOT_QUERY = "copilot:query"
    TICKET_CREATE = "ticket:create"
    AUDIT_READ = "audit:read"
    DETECTION_READ = "detection:read"
    DETECTION_WRITE = "detection:write"
    HUNT_RUN = "hunt:run"
    ADMIN = "admin:*"


# RBAC matrix — least privilege per role.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SUPER_ADMIN: frozenset(Permission),
    Role.SOC_MANAGER: frozenset(
        {
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.TICKET_CREATE,
            Permission.AUDIT_READ,
            Permission.DETECTION_READ,
        }
    ),
    Role.TIER1: frozenset(
        {
            Permission.INVESTIGATION_READ,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.DETECTION_READ,
        }
    ),
    Role.TIER2: frozenset(
        {
            Permission.ALERT_INGEST,
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.TICKET_CREATE,
            Permission.DETECTION_READ,
            Permission.HUNT_RUN,
        }
    ),
    Role.TIER3: frozenset(
        {
            Permission.ALERT_INGEST,
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.INVESTIGATION_ACT,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.TICKET_CREATE,
            Permission.DETECTION_READ,
            Permission.DETECTION_WRITE,
            Permission.HUNT_RUN,
        }
    ),
    Role.THREAT_HUNTER: frozenset(
        {
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.DETECTION_READ,
            Permission.DETECTION_WRITE,
            Permission.HUNT_RUN,
        }
    ),
    Role.INCIDENT_RESPONDER: frozenset(
        {
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.INVESTIGATION_ACT,
            Permission.IOC_READ,
            Permission.COPILOT_QUERY,
            Permission.TICKET_CREATE,
            Permission.DETECTION_READ,
            Permission.HUNT_RUN,
        }
    ),
    Role.AUDITOR: frozenset(
        {Permission.INVESTIGATION_READ, Permission.AUDIT_READ, Permission.DETECTION_READ}
    ),
}


def permissions_for(principal: Principal) -> frozenset[Permission]:
    perms: set[Permission] = set()
    for role_name in principal.roles:
        try:
            perms |= ROLE_PERMISSIONS.get(Role(role_name), frozenset())
        except ValueError:
            continue  # unknown role → no grant
    return frozenset(perms)


def has_permission(principal: Principal, perm: Permission) -> bool:
    grants = permissions_for(principal)
    return Permission.ADMIN in grants or perm in grants


def require_permission(principal: Principal, perm: Permission) -> None:
    if not has_permission(principal, perm):
        raise ForbiddenError(f"Missing permission: {perm}")


@dataclass(frozen=True)
class ResourceContext:
    """Attributes of the resource being accessed, for ABAC."""

    tenant: str
    sensitivity: str = "standard"  # standard | restricted | crown_jewel
    owner_subject: str | None = None


def abac_check(principal: Principal, resource: ResourceContext) -> None:
    """Attribute-based gate applied *after* RBAC succeeds."""
    if principal.tenant != resource.tenant:
        raise ForbiddenError("Cross-tenant access denied")

    if resource.sensitivity == "crown_jewel":
        clearance = principal.attributes.get("asset_clearance", "standard")
        if clearance not in {"restricted", "crown_jewel"} and not _is_privileged(principal):
            raise ForbiddenError("Insufficient clearance for crown-jewel asset")


def _is_privileged(principal: Principal) -> bool:
    return bool(
        {Role.SUPER_ADMIN.value, Role.SOC_MANAGER.value, Role.INCIDENT_RESPONDER.value}
        & principal.roles
    )
