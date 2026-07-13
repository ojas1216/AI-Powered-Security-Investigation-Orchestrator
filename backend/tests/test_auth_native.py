"""Native auth tests: register/login/session tokens/Google sign-in/RBAC wiring."""
from __future__ import annotations

import time
import uuid

import httpx
import pytest
import respx
from jose import jwt

import app.api.v1.routes.auth as auth_routes
from app.core import accounts
from app.core.accounts import (
    GOOGLE_JWKS_URL,
    UserAccount,
    UserStore,
    hash_password,
    issue_session_token,
    verify_password,
)
from app.core.config import settings
from app.core.security import decode_token


@pytest.fixture(autouse=True)
def fresh_user_store(monkeypatch):
    """Isolate accounts and disable the per-IP throttle window between tests."""
    store = UserStore()
    monkeypatch.setattr(accounts, "_store", store)
    monkeypatch.setattr(auth_routes, "_hits", {})
    return store


def make_user(**overrides) -> UserAccount:
    defaults = dict(
        subject=str(uuid.uuid4()), email="ana@example.com",
        display_name="Ana", tenant="acme", roles=("tier1_analyst",),
        provider="password", password_hash=hash_password("s3cure-pass-123"),
    )
    defaults.update(overrides)
    return UserAccount(**defaults)


# ---------------------------------------------------------------- passwords


def test_password_hashing_roundtrip_and_tamper_resistance():
    stored = hash_password("correct horse battery staple")
    assert stored.startswith("pbkdf2$")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong password", stored)
    assert not verify_password("anything", "garbage")


def test_session_token_is_accepted_by_the_api_token_decoder():
    user = make_user()
    token, ttl = issue_session_token(user)
    claims = decode_token(token)  # the same path every API request uses
    assert claims["preferred_username"] == user.email
    assert claims["tenant"] == "acme"
    assert claims["realm_access"]["roles"] == ["tier1_analyst"]
    assert ttl == int(settings.session_ttl_hours * 3600)


def test_forged_session_token_is_rejected():
    from app.core.exceptions import AuthError

    forged = jwt.encode(
        {"iss": "aegisflow", "aud": settings.oidc_audience, "sub": "x",
         "tenant": "acme", "iat": int(time.time()), "exp": int(time.time()) + 60},
        "wrong-secret", algorithm="HS256")
    with pytest.raises(AuthError):
        decode_token(forged)


# ---------------------------------------------------------------- API flows


def test_register_login_and_use_the_platform(client):
    reg = client.post("/api/v1/auth/register", json={
        "email": "new.analyst@example.com", "password": "very-long-password-1",
        "display_name": "New Analyst",
    })
    assert reg.status_code == 201, reg.text
    body = reg.json()
    assert body["tenant"] == settings.default_tenant
    assert body["roles"] == [settings.default_user_role]

    # Duplicate registration conflicts.
    dup = client.post("/api/v1/auth/register", json={
        "email": "new.analyst@example.com", "password": "very-long-password-1"})
    assert dup.status_code == 409

    login = client.post("/api/v1/auth/login", json={
        "email": "new.analyst@example.com", "password": "very-long-password-1"})
    assert login.status_code == 200
    token = login.json()["access_token"]

    # The session token works on protected routes with tier1 permissions.
    me = client.get("/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert "investigation:read" in me.json()["permissions"]
    listed = client.get("/api/v1/investigations",
                        headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    # ...but least-privilege: tier1 cannot ingest alerts.
    denied = client.post("/api/v1/alerts/ingest", json={"source": "generic"},
                         headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403


def test_login_gives_uniform_error_for_unknown_email_and_wrong_password(client):
    client.post("/api/v1/auth/register", json={
        "email": "someone@example.com", "password": "very-long-password-1"})
    wrong_pw = client.post("/api/v1/auth/login", json={
        "email": "someone@example.com", "password": "incorrect-password"})
    unknown = client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com", "password": "incorrect-password"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()  # no account probing


def test_weak_registrations_rejected(client):
    assert client.post("/api/v1/auth/register", json={
        "email": "not-an-email", "password": "very-long-password-1",
    }).status_code == 400
    assert client.post("/api/v1/auth/register", json={
        "email": "ok@example.com", "password": "short",
    }).status_code == 400


def test_auth_endpoints_are_rate_limited(client):
    for _ in range(10):
        client.post("/api/v1/auth/login",
                    json={"email": "x@example.com", "password": "p" * 10})
    resp = client.post("/api/v1/auth/login",
                       json={"email": "x@example.com", "password": "p" * 10})
    assert resp.status_code == 429


# ---------------------------------------------------------------- google

# Test-only RSA keypair for signing a fake Google ID token.
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIVATE_PEM = _RSA_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()).decode()


def _google_jwks() -> dict:
    from jose import jwk

    key = jwk.construct(
        _RSA_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        algorithm="RS256")
    return {"keys": [{**key.to_dict(), "kid": "g-test-key", "use": "sig"}]}


def _google_token(**overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "test-google-client-id",
        "sub": "1234567890",
        "email": "gsuite.user@example.com",
        "email_verified": True,
        "name": "GSuite User",
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return jwt.encode(claims, _PRIVATE_PEM, algorithm="RS256",
                      headers={"kid": "g-test-key"})


@pytest.fixture()
def google_configured(monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    # fresh JWKS cache per test
    import app.core.security as security

    monkeypatch.setattr(security, "_jwks_by_url",
                        {settings.oidc_jwks_url: security._jwks})


@respx.mock
def test_google_sign_in_auto_provisions_and_signs_in(client, google_configured):
    respx.get(GOOGLE_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_google_jwks()))

    resp = client.post("/api/v1/auth/google",
                       json={"credential": _google_token()})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["email"] == "gsuite.user@example.com"
    assert body["roles"] == [settings.default_user_role]

    # The issued session works on the API.
    me = client.get("/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == "gsuite.user@example.com"

    # Second sign-in reuses the account (no duplicate).
    again = client.post("/api/v1/auth/google",
                        json={"credential": _google_token()})
    assert again.status_code == 200


@respx.mock
def test_google_token_for_another_app_is_rejected(client, google_configured):
    respx.get(GOOGLE_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_google_jwks()))
    resp = client.post("/api/v1/auth/google", json={
        "credential": _google_token(aud="someone-elses-client-id")})
    assert resp.status_code == 401


@respx.mock
def test_google_unverified_email_is_rejected(client, google_configured):
    respx.get(GOOGLE_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_google_jwks()))
    resp = client.post("/api/v1/auth/google", json={
        "credential": _google_token(email_verified=False)})
    assert resp.status_code == 401


def test_google_disabled_without_client_id(client):
    resp = client.post("/api/v1/auth/google", json={"credential": "x"})
    assert resp.status_code == 503
