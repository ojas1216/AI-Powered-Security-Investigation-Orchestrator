# AegisFlow Security Posture

Built to OWASP ASVS L2+, OWASP Top 10, NIST SSDF, CIS Controls, and Zero Trust.
Assume hostile internet exposure.

## Authentication
- Delegated to **Keycloak** (OIDC / OAuth 2.1). We never implement custom auth.
- API validates RS256 JWTs against the realm JWKS (cached, key-rotation aware),
  checking `iss`, `aud`, `exp`, `nbf`. See `app/core/security.py`.
- MFA + refresh-token rotation enforced in Keycloak realm config (`infra/keycloak`).

## Authorization
- **RBAC + ABAC** in `app/core/authz.py`. Roles: SuperAdmin, SocManager, Tier1/2/3,
  ThreatHunter, IncidentResponder, Auditor.
- Every route declares a `Permission`; `require(perm)` dependency enforces it.
- ABAC adds attribute rules (tenant match, asset sensitivity, ownership) — an analyst
  cannot read an investigation outside their tenant even with the right role.

## Multi-tenancy
- `X-Tenant-ID` (or JWT `tenant` claim) → `TenantContext` per request.
- Postgres **Row-Level Security**: every tenant-scoped table has an RLS policy keyed on
  `current_setting('app.tenant_id')`, set per transaction. App bugs cannot cross tenants.

## Injection / web
- SQL: SQLAlchemy ORM + bound parameters only. No string SQL.
- Command injection: no shell; connectors use typed HTTP clients.
- **SSRF:** outbound enrichment URLs pass `app/core/ssrf.py` allow-list + private-range
  block before any request. User-supplied URLs are never fetched server-side directly.
- XSS: API is JSON-only; frontend never uses `dangerouslySetInnerHTML`; strict CSP.
- CSRF: SameSite=strict, double-submit token for cookie auth flows.
- XXE: defused XML parsing for any sandbox/email artifact parsing.
- IDOR: object access always filtered by tenant + ABAC, never by raw client id alone.

## Secrets
- HashiCorp Vault + External Secrets Operator. No hardcoded credentials anywhere.
- Gitleaks runs in CI and as a pre-commit hook.

## API hardening
- Pydantic input + output validation, request size limits, per-tenant rate limiting
  (Redis token bucket), OpenAPI-validated.

## Containers / K8s
- Distroless, non-root, read-only rootfs, dropped caps. Images signed (cosign), SBOM
  (Syft) attached. Network policies, namespace isolation, Pod Security Standards
  (restricted), Istio mTLS.

## AI security
- **Prompt injection:** all untrusted text (emails, sandbox notes, IOC context) is wrapped
  and delimited; the system prompt forbids instruction-following from data; `copilot/guards.py`
  strips known jailbreak markers and caps context.
- **RAG poisoning:** retrieved snippets are tenant-scoped, source-attributed, and never
  treated as instructions.
- **No tool execution from LLM:** the copilot returns structured *recommendations*; actions
  require a signed playbook + human approval. Output is schema-validated before storage.

## Supply chain / CI gates
Semgrep (SAST), Trivy + Grype (deps/images), Gitleaks (secrets), Checkov (IaC),
Syft (SBOM), Bandit. CI **fails on Critical**. See `.github/workflows/`.

## Audit logging
Every state-changing action emits a tamper-evident audit event (actor, tenant, action,
target, result) to the `audit_log` table and Loki.

Report vulnerabilities: security@aegisflow.example (see SECURITY.md disclosure policy).
