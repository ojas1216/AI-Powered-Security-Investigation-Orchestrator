# Authentication & Authorization

AegisFlow delegates identity to **Keycloak** (OIDC / OAuth 2.1). The API only
*verifies* tokens — it never issues or stores credentials. See `app/core/security.py`
(JWT/JWKS validation) and `app/core/authz.py` (RBAC + ABAC).

## Two run modes

| Mode | When | Auth |
| ---- | ---- | ---- |
| **Local dev** (`run.ps1`, tests) | quick, offline | `AEGIS_AUTH_DEV_BYPASS=true` trusts headers — **local env only**; the app refuses to boot with it on outside `env=local` |
| **Compose / prod** (`docker compose up`) | full stack | Real Keycloak; bypass OFF. Tokens validated against the realm JWKS |

## Demo realm

`infra/keycloak/realm-aegisflow.json` is auto-imported. Client `aegisflow-api`
(secret `aegisflow-api-secret`) with an audience mapper (`aud=aegisflow-api`) and a
`tenant` claim mapper. Demo users:

| User | Password | Tenant | Realm role |
| ---- | -------- | ------ | ---------- |
| `analyst` | `analyst-pass` | acme | `tier3_analyst` |
| `manager` | `manager-pass` | acme | `soc_manager` |
| `globex-analyst` | `globex-pass` | globex | `tier3_analyst` |

## Get a token (password grant, for testing)

```bash
curl -s -X POST http://localhost:8080/realms/aegisflow/protocol/openid-connect/token \
  -d grant_type=password -d client_id=aegisflow-api -d client_secret=aegisflow-api-secret \
  -d username=analyst -d password=analyst-pass -d scope=openid | jq -r .access_token
```

Then call the API with `Authorization: Bearer <token>`. The **tenant is taken from the
signed `tenant` claim** — supplying a mismatching `X-Tenant-ID` header is rejected (401),
so a client cannot select a tenant it is not scoped to.

## Verified behavior (end-to-end, against a real Keycloak 26)

| Case | Result |
| ---- | ------ |
| Valid `analyst` token → `POST /alerts/ingest` | `201` |
| No token | `401` |
| Tampered token (bad signature) | `401` |
| `X-Tenant-ID: globex` with an acme token | `401` (tenant spoof blocked) |
| `manager` (soc_manager, no `alert:ingest`) → ingest | `403` (RBAC) |
| `manager` → `GET /investigations` (has `investigation:read`) | `200` |

## Production hardening (realm config)

Enable MFA (OTP/WebAuthn required action), refresh-token rotation, short access-token
lifetimes, and brute-force protection (already on in the demo realm). Replace the demo
client secret with a Vault-sourced secret. Use a stable `KC_HOSTNAME` and HTTPS.
