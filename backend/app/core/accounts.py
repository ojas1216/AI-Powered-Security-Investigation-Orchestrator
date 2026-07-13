"""Native user accounts: registration, password + Google sign-in, session tokens.

Three ways into the platform now coexist:
  1. Keycloak OIDC (enterprise SSO) — verified in security.py, unchanged.
  2. Native accounts — email + password, PBKDF2-HMAC-SHA256 (390k iterations,
     per-user salt, constant-time compare). We never store plaintext.
  3. Google Sign-In — the SPA obtains a Google ID token (GIS button); we verify
     it server-side against Google's JWKS (signature, issuer, audience =
     AEGIS_GOOGLE_CLIENT_ID, expiry, email_verified) and auto-provision the
     account on first sign-in.

All three produce the same thing: a short-lived HS256 session JWT carrying
sub/email/tenant/roles that the API's normal RBAC pipeline consumes. Sign-out
is client-side token disposal (stateless API).

New users get the least-privileged analyst role in the default tenant; an admin
promotes them (RBAC matrix in authz.py) — self-registration can never mint
privileged principals.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from jose import jwt
from jose.exceptions import JWTError

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.logging import get_logger

log = get_logger("accounts")

SESSION_ISSUER = "aegisflow"
_PBKDF2_ITERATIONS = 390_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MIN_PASSWORD_LEN = 10

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
_GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}


class RegistrationError(Exception):
    """Invalid registration input or duplicate account; maps to 400/409."""


@dataclass
class UserAccount:
    subject: str
    email: str
    display_name: str
    tenant: str
    roles: tuple[str, ...]
    provider: str  # "password" | "google"
    password_hash: str = ""  # "pbkdf2$<iterations>$<salt-hex>$<hash-hex>"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------- password


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _scheme, iterations, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def validate_registration(email: str, password: str) -> None:
    if not _EMAIL_RE.match(email):
        raise RegistrationError("invalid email address")
    if len(password) < _MIN_PASSWORD_LEN:
        raise RegistrationError(
            f"password must be at least {_MIN_PASSWORD_LEN} characters")


# ---------------------------------------------------------------- store


class UserStore:
    """Thread-safe in-memory account store (hermetic default)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_email: dict[str, UserAccount] = {}

    def create(self, user: UserAccount) -> UserAccount:
        key = user.email.lower()
        with self._lock:
            if key in self._by_email:
                raise RegistrationError("an account with this email already exists")
            self._by_email[key] = user
        log.info("user_registered", email=user.email, provider=user.provider,
                 tenant=user.tenant)
        return user

    def get_by_email(self, email: str) -> UserAccount | None:
        with self._lock:
            return self._by_email.get(email.lower())


class PostgresUserStore:
    """Durable account store; same interface as UserStore."""

    def create(self, user: UserAccount) -> UserAccount:
        from app.core.tenancy import set_current_tenant
        from app.db.models import UserAccountRecord
        from app.db.session import tenant_session

        set_current_tenant(user.tenant)
        with tenant_session() as session:
            exists = (
                session.query(UserAccountRecord)
                .filter(UserAccountRecord.email == user.email.lower())
                .one_or_none()
            )
            if exists is not None:
                raise RegistrationError("an account with this email already exists")
            session.add(UserAccountRecord(
                id=user.subject,
                tenant_id=user.tenant,
                email=user.email.lower(),
                display_name=user.display_name,
                roles=list(user.roles),
                provider=user.provider,
                password_hash=user.password_hash,
            ))
        log.info("user_registered", email=user.email, provider=user.provider,
                 tenant=user.tenant, backend="postgres")
        return user

    def get_by_email(self, email: str) -> UserAccount | None:
        from app.core.tenancy import set_current_tenant
        from app.db.models import UserAccountRecord
        from app.db.session import tenant_session

        # Accounts are global at sign-in time (the user's tenant is not yet
        # known); the users table carries no RLS policy for exactly this reason.
        set_current_tenant(settings.default_tenant)
        with tenant_session() as session:
            rec = (
                session.query(UserAccountRecord)
                .filter(UserAccountRecord.email == email.lower())
                .one_or_none()
            )
            if rec is None:
                return None
            return UserAccount(
                subject=rec.id, email=rec.email, display_name=rec.display_name,
                tenant=rec.tenant_id, roles=tuple(rec.roles or ()),
                provider=rec.provider, password_hash=rec.password_hash or "",
            )


_store: UserStore | PostgresUserStore | None = None


def build_user_store() -> UserStore | PostgresUserStore:
    global _store
    if _store is None:
        _store = PostgresUserStore() if settings.use_postgres else UserStore()
    return _store


# ---------------------------------------------------------------- sessions


def issue_session_token(user: UserAccount) -> tuple[str, int]:
    """Return (HS256 session JWT, ttl seconds) for a signed-in account."""
    ttl = int(settings.session_ttl_hours * 3600)
    now = int(time.time())
    claims = {
        "iss": SESSION_ISSUER,
        "aud": settings.oidc_audience,
        "sub": user.subject,
        "preferred_username": user.email,
        "name": user.display_name,
        "tenant": user.tenant,
        "realm_access": {"roles": list(user.roles)},
        "provider": user.provider,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(claims, settings.secret_key, algorithm="HS256"), ttl


def decode_session_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, settings.secret_key, algorithms=["HS256"],
            audience=settings.oidc_audience, issuer=SESSION_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except JWTError as exc:
        raise AuthError("Invalid or expired session token") from exc


# ---------------------------------------------------------------- google


def verify_google_id_token(credential: str, *, jwks_url: str = GOOGLE_JWKS_URL) -> dict:
    """Verify a Google ID token; returns its claims. Raises AuthError."""
    if not settings.google_client_id:
        raise AuthError("Google sign-in is not configured (AEGIS_GOOGLE_CLIENT_ID)")
    from app.core.security import fetch_signing_key  # shared JWKS cache

    try:
        header = jwt.get_unverified_header(credential)
        key = fetch_signing_key(jwks_url, header["kid"])
        claims = jwt.decode(
            credential, key, algorithms=["RS256"],
            audience=settings.google_client_id,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except (JWTError, KeyError) as exc:
        raise AuthError("Invalid Google credential") from exc
    if claims.get("iss") not in _GOOGLE_ISSUERS:
        raise AuthError("Invalid Google credential issuer")
    if not claims.get("email") or not claims.get("email_verified"):
        raise AuthError("Google account email is not verified")
    return claims


def sign_in_with_google(credential: str) -> tuple[UserAccount, str, int]:
    """Verify the Google credential; auto-provision on first sign-in."""
    claims = verify_google_id_token(credential)
    store = build_user_store()
    email = str(claims["email"])
    user = store.get_by_email(email)
    if user is None:
        if not settings.allow_self_registration:
            raise AuthError("Self-registration is disabled; ask an administrator")
        user = store.create(UserAccount(
            subject=str(uuid.uuid4()),
            email=email,
            display_name=str(claims.get("name") or email.split("@")[0]),
            tenant=settings.default_tenant,
            roles=(settings.default_user_role,),
            provider="google",
        ))
    token, ttl = issue_session_token(user)
    log.info("google_sign_in", email=email, tenant=user.tenant)
    return user, token, ttl
