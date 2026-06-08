"""Authentication: OIDC/JWT validation against Keycloak.

We delegate identity to Keycloak and only *verify* tokens here. We never issue,
store, or compare passwords. Validation checks signature (RS256 via JWKS),
issuer, audience, and expiry.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from jose import jwt
from jose.exceptions import JWTError

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.logging import get_logger

log = get_logger("auth")


@dataclass(frozen=True)
class Principal:
    """The authenticated caller for a request."""

    subject: str
    username: str
    tenant: str
    roles: frozenset[str]
    attributes: dict[str, str] = field(default_factory=dict)


class _JwksCache:
    """Caches Keycloak signing keys; refreshes on rotation/miss."""

    def __init__(self, jwks_url: str, ttl: int = 3600) -> None:
        self._url = jwks_url
        self._ttl = ttl
        self._keys: dict[str, dict] = {}
        self._fetched_at = 0.0

    def _refresh(self) -> None:
        try:
            resp = httpx.get(self._url, timeout=5.0)
            resp.raise_for_status()
            self._keys = {k["kid"]: k for k in resp.json().get("keys", [])}
            self._fetched_at = time.time()
        except httpx.HTTPError as exc:  # pragma: no cover - network
            log.error("jwks_fetch_failed", error=str(exc))
            raise AuthError("Unable to fetch signing keys") from exc

    def get(self, kid: str) -> dict:
        if kid not in self._keys or (time.time() - self._fetched_at) > self._ttl:
            self._refresh()
        if kid not in self._keys:
            self._refresh()  # key rotation: force one more refresh
        if kid not in self._keys:
            raise AuthError("Unknown signing key")
        return self._keys[kid]


_jwks = _JwksCache(settings.oidc_jwks_url)


def decode_token(token: str) -> dict:
    """Verify and decode a bearer JWT. Raises AuthError on any failure."""
    try:
        header = jwt.get_unverified_header(token)
        key = _jwks.get(header["kid"])
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except (JWTError, KeyError) as exc:
        raise AuthError("Invalid or expired token") from exc


def principal_from_claims(claims: dict, tenant_header: str | None = None) -> Principal:
    """Build a Principal from verified claims.

    Tenant is taken from the signed `tenant` claim. A mismatching X-Tenant-ID
    header is rejected — clients cannot select a tenant they aren't scoped to.
    """
    tenant = claims.get("tenant") or claims.get("org")
    if not tenant:
        raise AuthError("Token missing tenant claim")
    if tenant_header and tenant_header != tenant:
        raise AuthError("Tenant header does not match token tenant")

    realm_roles = claims.get("realm_access", {}).get("roles", [])
    return Principal(
        subject=claims["sub"],
        username=claims.get("preferred_username", claims["sub"]),
        tenant=str(tenant),
        roles=frozenset(realm_roles),
        attributes={
            "asset_clearance": str(claims.get("asset_clearance", "standard")),
            "tier": str(claims.get("tier", "")),
        },
    )
