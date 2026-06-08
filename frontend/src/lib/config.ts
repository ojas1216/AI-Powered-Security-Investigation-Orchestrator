/**
 * Runtime configuration, sourced from Vite env (VITE_*). No secrets live here —
 * the SPA authenticates against a PUBLIC Keycloak client (PKCE/no secret).
 */
function env(key: string, fallback: string): string {
  const v = (import.meta.env as Record<string, string | undefined>)[key];
  return v ?? fallback;
}

export const config = {
  /** Backend API base. Dev server proxies /api -> http://localhost:8000. */
  apiBaseUrl: env("VITE_API_BASE_URL", "/api/v1"),

  oidc: {
    /** Keycloak base, e.g. http://localhost:8080 */
    url: env("VITE_OIDC_URL", "http://localhost:8080"),
    realm: env("VITE_OIDC_REALM", "aegisflow"),
    /** Public SPA client (no secret). Tokens carry aud=aegisflow-api via a mapper. */
    clientId: env("VITE_OIDC_CLIENT_ID", "aegisflow-spa"),
  },

  /** Allow the header-based dev login (only works when the API runs with
   *  AEGIS_AUTH_DEV_BYPASS=true). Disabled automatically in production builds. */
  devLoginEnabled: env("VITE_DEV_LOGIN", import.meta.env.PROD ? "false" : "true") === "true",

  app: {
    name: "AegisFlow",
    tagline: "AI-Powered Security Investigation Orchestrator",
    version: "1.0.0",
  },
} as const;

export function tokenEndpoint(): string {
  return `${config.oidc.url}/realms/${config.oidc.realm}/protocol/openid-connect/token`;
}
