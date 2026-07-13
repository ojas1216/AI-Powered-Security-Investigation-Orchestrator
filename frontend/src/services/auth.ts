import axios from "axios";
import { config, tokenEndpoint } from "@/lib/config";

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}

/**
 * Resource-Owner Password grant against the PUBLIC SPA client (no secret in the
 * bundle). Adequate for on-prem SOC SSO + the demo realm. For internet-facing
 * deployments, swap this for the Authorization-Code + PKCE redirect flow (the
 * public client is already PKCE-capable) — the rest of the app is unchanged.
 */
export async function loginWithPassword(
  username: string,
  password: string,
): Promise<{ accessToken: string; refreshToken: string | null; expiresIn: number }> {
  const form = new URLSearchParams();
  form.set("grant_type", "password");
  form.set("client_id", config.oidc.clientId);
  form.set("username", username);
  form.set("password", password);
  form.set("scope", "openid");

  const { data } = await axios.post<TokenResponse>(tokenEndpoint(), form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15_000,
  });
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? null,
    expiresIn: data.expires_in,
  };
}

export async function refreshAccessToken(
  refreshToken: string,
): Promise<{ accessToken: string; refreshToken: string | null; expiresIn: number }> {
  const form = new URLSearchParams();
  form.set("grant_type", "refresh_token");
  form.set("client_id", config.oidc.clientId);
  form.set("refresh_token", refreshToken);

  const { data } = await axios.post<TokenResponse>(tokenEndpoint(), form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15_000,
  });
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? null,
    expiresIn: data.expires_in,
  };
}

// ── Native accounts + Google sign-in (AegisFlow /auth endpoints) ─────────────

import { http } from "./http";

export interface SessionResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  email: string;
  display_name: string;
  tenant: string;
  roles: string[];
}

export async function registerUser(
  email: string,
  password: string,
  displayName: string,
): Promise<SessionResponse> {
  const { data } = await http.post<SessionResponse>("/auth/register", {
    email,
    password,
    display_name: displayName,
  });
  return data;
}

export async function loginNative(email: string, password: string): Promise<SessionResponse> {
  const { data } = await http.post<SessionResponse>("/auth/login", { email, password });
  return data;
}

/** Exchange a Google ID token (from the GIS button) for an AegisFlow session. */
export async function loginWithGoogle(credential: string): Promise<SessionResponse> {
  const { data } = await http.post<SessionResponse>("/auth/google", { credential });
  return data;
}
