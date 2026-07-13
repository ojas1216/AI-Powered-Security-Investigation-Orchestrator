"""Shared FastAPI dependencies: authentication, tenancy, authorization, rate limit."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, Request

from app.core.authz import Permission, require_permission
from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.security import Principal, decode_token, principal_from_claims
from app.core.tenancy import set_current_tenant
from app.ratelimit import check_rate_limit


async def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_tenant_id: str | None = Header(default=None),
) -> Principal:
    """Authenticate the caller and bind the tenant context.

    Dev bypass (local only) lets the platform run without a Keycloak instance by
    trusting headers — guarded so it can never be enabled outside `env=local`.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("Missing bearer token")
    bearer = authorization.split(" ", 1)[1].strip()

    # Dev bypass applies ONLY to the literal "dev" token (what the local UI's
    # dev-login sends). Real JWTs always go through verification, so native
    # accounts and Google sign-in behave identically in local mode.
    if settings.auth_dev_bypass and settings.is_local and bearer == "dev":
        tenant = x_tenant_id or "demo"
        roles = (request.headers.get("X-Roles") or "tier3_analyst").split(",")
        principal = Principal(
            subject="dev-user", username="dev-user", tenant=tenant.lower(),
            roles=frozenset(r.strip() for r in roles),
            attributes={"asset_clearance": "restricted"},
        )
        set_current_tenant(principal.tenant)
        return principal

    claims = decode_token(bearer)
    principal = principal_from_claims(claims, tenant_header=x_tenant_id)
    set_current_tenant(principal.tenant)
    await check_rate_limit(principal.tenant)
    return principal


def require(perm: Permission) -> Callable[..., Principal]:
    """Dependency factory enforcing an RBAC permission on a route."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        require_permission(principal, perm)
        return principal

    return _dep
