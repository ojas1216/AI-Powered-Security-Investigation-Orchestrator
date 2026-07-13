/**
 * Client-side RBAC mirror of backend/app/core/authz.py. This gates UI affordances
 * only — the API independently enforces every permission, so a tampered client
 * cannot gain access. Keep in sync with the backend matrix.
 */
export type Role =
  | "super_admin"
  | "soc_manager"
  | "tier1_analyst"
  | "tier2_analyst"
  | "tier3_analyst"
  | "threat_hunter"
  | "incident_responder"
  | "auditor";

export type Permission =
  | "alert:ingest"
  | "investigation:read"
  | "investigation:create"
  | "investigation:act"
  | "ioc:read"
  | "copilot:query"
  | "ticket:create"
  | "audit:read"
  | "detection:read"
  | "detection:write"
  | "hunt:run"
  | "admin:*";

const ALL: Permission[] = [
  "alert:ingest",
  "investigation:read",
  "investigation:create",
  "investigation:act",
  "ioc:read",
  "copilot:query",
  "ticket:create",
  "audit:read",
  "detection:read",
  "detection:write",
  "hunt:run",
  "admin:*",
];

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  super_admin: ALL,
  soc_manager: [
    "investigation:read",
    "investigation:create",
    "ioc:read",
    "copilot:query",
    "ticket:create",
    "audit:read",
    "detection:read",
  ],
  tier1_analyst: ["investigation:read", "ioc:read", "copilot:query", "detection:read"],
  tier2_analyst: [
    "alert:ingest",
    "investigation:read",
    "investigation:create",
    "ioc:read",
    "copilot:query",
    "ticket:create",
    "detection:read",
    "hunt:run",
  ],
  tier3_analyst: [
    "alert:ingest",
    "investigation:read",
    "investigation:create",
    "investigation:act",
    "ioc:read",
    "copilot:query",
    "ticket:create",
    "detection:read",
    "detection:write",
    "hunt:run",
  ],
  threat_hunter: [
    "investigation:read",
    "investigation:create",
    "ioc:read",
    "copilot:query",
    "detection:read",
    "detection:write",
    "hunt:run",
  ],
  incident_responder: [
    "investigation:read",
    "investigation:create",
    "investigation:act",
    "ioc:read",
    "copilot:query",
    "ticket:create",
    "detection:read",
    "hunt:run",
  ],
  auditor: ["investigation:read", "audit:read", "detection:read"],
};

export function permissionsForRoles(roles: string[]): Set<Permission> {
  const perms = new Set<Permission>();
  for (const r of roles) {
    const list = ROLE_PERMISSIONS[r as Role];
    if (list) list.forEach((p) => perms.add(p));
  }
  return perms;
}

export function hasPermission(roles: string[], perm: Permission): boolean {
  const perms = permissionsForRoles(roles);
  return perms.has("admin:*") || perms.has(perm);
}
