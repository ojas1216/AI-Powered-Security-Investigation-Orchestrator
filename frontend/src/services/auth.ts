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
