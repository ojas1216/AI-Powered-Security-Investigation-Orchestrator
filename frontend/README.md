# AegisFlow Frontend

React + TypeScript + Vite + Tailwind investigation console.

```bash
npm install
npm run dev   # http://localhost:5173, proxies /api → http://localhost:8000
```

Security notes:
- Strict CSP in `index.html` (no inline scripts, locked `connect-src`).
- No `dangerouslySetInnerHTML` anywhere — all rendering is text-content only.
- Auth token/tenant held in memory (not `localStorage`) to limit XSS blast radius.
  In production the token comes from the Keycloak OIDC flow via the gateway.
