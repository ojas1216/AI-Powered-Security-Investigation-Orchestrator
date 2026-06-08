import axios, { AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from "axios";
import { config } from "@/lib/config";
import { useAuthStore } from "@/stores/auth";
import type { ApiError } from "@/types/api";

/** Emitted when the API rejects our credentials so the app can force re-login. */
export const AUTH_EXPIRED_EVENT = "aegis:auth-expired";

export const http: AxiosInstance = axios.create({
  baseURL: config.apiBaseUrl,
  timeout: 30_000,
  // We do NOT send cookies for the API (token is a bearer in memory); this also
  // sidesteps CSRF on the API surface.
  withCredentials: false,
});

// ── Request interceptor: attach auth + tenant context ────────────────────────
http.interceptors.request.use((cfg: InternalAxiosRequestConfig) => {
  const { token, mode, user } = useAuthStore.getState();
  if (token) cfg.headers.set("Authorization", `Bearer ${token}`);
  // Dev-bypass mode authenticates via headers (only honored by a local API with
  // AEGIS_AUTH_DEV_BYPASS=true). In OIDC mode the tenant comes from the signed token.
  if (mode === "dev" && user) {
    cfg.headers.set("X-Tenant-ID", user.tenant);
    cfg.headers.set("X-Roles", user.roles.join(","));
  }
  cfg.headers.set("X-Request-ID", crypto.randomUUID());
  return cfg;
});

// ── Response interceptor: retry transient errors, normalize, handle 401 ──────
http.interceptors.response.use(
  (res) => res,
  async (error: AxiosError<ApiError>) => {
    const cfg = error.config as (InternalAxiosRequestConfig & { _retry?: number }) | undefined;

    // Bounded retry for network errors / 502 / 503 / 504 with backoff.
    const status = error.response?.status;
    const retriable = !error.response || (status !== undefined && [502, 503, 504].includes(status));
    if (cfg && retriable && (cfg._retry ?? 0) < 2 && (cfg.method ?? "get").toLowerCase() === "get") {
      cfg._retry = (cfg._retry ?? 0) + 1;
      await new Promise((r) => setTimeout(r, 300 * cfg._retry!));
      return http(cfg);
    }

    if (status === 401) {
      useAuthStore.getState().clear();
      window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
    }

    return Promise.reject(normalizeError(error));
  },
);

export interface NormalizedError {
  status: number;
  code: string;
  message: string;
}

export function normalizeError(error: AxiosError<ApiError>): NormalizedError {
  const status = error.response?.status ?? 0;
  const body = error.response?.data;
  return {
    status,
    code: body?.error?.code ?? (status === 0 ? "network_error" : "error"),
    message:
      body?.error?.message ??
      (status === 0 ? "Cannot reach the AegisFlow API." : error.message || "Request failed"),
  };
}
