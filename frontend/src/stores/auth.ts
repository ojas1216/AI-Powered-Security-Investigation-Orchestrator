import { create } from "zustand";
import { decodeJwt } from "@/security/jwt";
import { hasPermission, type Permission } from "@/lib/rbac";

export interface AuthUser {
  subject: string;
  username: string;
  tenant: string;
  roles: string[];
}

interface AuthState {
  mode: "oidc" | "dev" | null;
  /** Access token kept in MEMORY only — never localStorage/sessionStorage. */
  token: string | null;
  refreshToken: string | null;
  expiresAt: number;
  user: AuthUser | null;

  setOidcSession: (accessToken: string, refreshToken: string | null, expiresIn: number) => void;
  setDevSession: (tenant: string, roles: string[]) => void;
  clear: () => void;
  isAuthenticated: () => boolean;
  can: (perm: Permission) => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  mode: null,
  token: null,
  refreshToken: null,
  expiresAt: 0,
  user: null,

  setOidcSession: (accessToken, refreshToken, expiresIn) => {
    const claims = decodeJwt(accessToken);
    if (!claims) throw new Error("Invalid token");
    set({
      mode: "oidc",
      token: accessToken,
      refreshToken,
      expiresAt: Date.now() + expiresIn * 1000,
      user: {
        subject: claims.sub,
        username: claims.preferred_username ?? claims.sub,
        tenant: String(claims.tenant ?? claims.org ?? ""),
        roles: claims.realm_access?.roles ?? [],
      },
    });
  },

  setDevSession: (tenant, roles) => {
    set({
      mode: "dev",
      token: "dev",
      refreshToken: null,
      expiresAt: Date.now() + 12 * 3600 * 1000,
      user: { subject: "dev-user", username: "dev-user", tenant, roles },
    });
  },

  clear: () => set({ mode: null, token: null, refreshToken: null, expiresAt: 0, user: null }),

  isAuthenticated: () => {
    const s = get();
    return !!s.token && Date.now() < s.expiresAt;
  },

  can: (perm) => {
    const u = get().user;
    return !!u && hasPermission(u.roles, perm);
  },
}));
