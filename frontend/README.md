# AegisFlow Frontend — Enterprise SOC Console

Production-grade React 19 + TypeScript + Vite 7 + Tailwind v4 frontend for the
AegisFlow investigation API. Dark-mode-first, optimized for Tier 1–3 analysts,
threat hunters, and SOC managers.

```bash
npm install
npm run dev      # http://localhost:5173 (proxies /api -> http://localhost:8000)
npm run build    # tsc --noEmit && vite build -> dist/
```

## What's wired to the live API (real data, no mocks)

| Area | Backend endpoint | Notes |
| ---- | ---------------- | ----- |
| Dashboard | `GET /investigations` | Metrics derived (open, malicious, MTTR, MITRE coverage, risk dist) |
| Alerts | `POST /alerts/ingest`, `GET /investigations` | Ingest sample alerts (RBAC `alert:ingest`) |
| Investigation workspace | `GET /investigations/{id}` | Overview, Timeline, Evidence, Threat Intel, MITRE, Graph, Notes, Reports |
| Threat Intel | `POST /iocs/extract` + aggregated IOCs | Live extract + multi-source enrichment |
| Attack Graph | investigation entities | React Flow (`@xyflow/react`) |
| MITRE ATT&CK | investigation techniques | Tactic/technique heatmap |
| AI Copilot | `POST /copilot/ask` | Grounded Q&A, guard-railed |
| Evidence Vault / Timeline / Reports | aggregated from investigations | Content-hashed evidence, exports (PDF/HTML/JSON) |
| Administration | `GET /readyz` + client audit | Health, RBAC matrix, session audit |

**Honest empty states** (no fabricated data) appear where the backend has no
endpoint yet: Cases, evidence download, and user/tenant/connector administration.
Each names the missing endpoint.

## Architecture

```
src/
  app/          App root, router, QueryClient
  routing/      ProtectedRoute, RoleGuard, ErrorBoundary, AppRoutes
  layouts→components/layout/  AppShell, Sidebar, Topbar, CommandPalette, NotificationCenter
  pages/        one file per route
  components/   ui/ (shadcn-style primitives) · common/ · investigation/ · graph/ · mitre/
  services/     axios client + interceptors, typed API services, Keycloak auth
  hooks/        TanStack Query hooks, audit
  stores/       Zustand: auth, ui, notifications, audit, notes
  lib/          config, rbac, nav, metrics, export, cn, sampleAlerts
  security/     Trusted Types policy, DOMPurify sanitizer, JWT decode
  types/        API contract mirror
```

## Security controls

- **Tokens in memory only** — never `localStorage`/`sessionStorage`.
- **Trusted Types** default policy backed by **DOMPurify**; **CSP** (incl.
  `require-trusted-types-for 'script'`) enforced by nginx in production.
- No `dangerouslySetInnerHTML` anywhere; all untrusted text rendered as text.
- **RBAC** mirror gates UI; the API independently enforces every permission + RLS.
- Tenant taken from the **signed** token; axios attaches it, the API validates it.
- Strict response headers, retry/backoff, 401 → forced re-login.

## Auth

The SPA authenticates against the **public** Keycloak client `aegisflow-spa`
(PKCE, no secret in the bundle) using the realm in
`infra/keycloak/realm-aegisflow.json`. Demo users: `analyst/analyst-pass`,
`manager/manager-pass`, `globex-analyst/globex-pass`. A local **dev-mode** button
(header auth) works when the API runs with `AEGIS_AUTH_DEV_BYPASS=true`.

For internet-facing deployments, switch the password grant in `services/auth.ts`
to Authorization-Code + PKCE redirect (the public client already supports it).

## Production image

`docker build -t aegisflow-web .` → distroless-style non-root `nginx-unprivileged`
on :8080, serving the SPA and proxying `/api` to the `api` service (compose).
