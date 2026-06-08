import type { ReactNode } from "react";
import { ShieldX } from "lucide-react";
import { useAuthStore } from "@/stores/auth";
import type { Permission } from "@/lib/rbac";

/** Renders children only if the principal holds `perm`; otherwise a 403 panel.
 *  The API enforces the same permission server-side regardless. */
export function RoleGuard({ perm, children }: { perm: Permission; children: ReactNode }) {
  const can = useAuthStore((s) => s.can(perm));
  if (!can) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <ShieldX className="h-9 w-9 text-high" />
        <h2 className="text-base font-semibold text-fg">Access denied</h2>
        <p className="max-w-sm text-sm text-fg-subtle">
          Your role does not grant <code className="text-fg">{perm}</code>. Contact your SOC
          manager if you believe this is an error.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}
