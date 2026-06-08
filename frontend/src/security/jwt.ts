/** Decode a JWT payload for display/claims (NOT for trust — the API verifies). */
export interface JwtClaims {
  sub: string;
  preferred_username?: string;
  tenant?: string;
  org?: string;
  exp?: number;
  realm_access?: { roles?: string[] };
  [k: string]: unknown;
}

export function decodeJwt(token: string): JwtClaims | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decodeURIComponent(escape(json))) as JwtClaims;
  } catch {
    return null;
  }
}
