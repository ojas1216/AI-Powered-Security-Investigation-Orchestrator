import { useCallback } from "react";
import { useAuditStore } from "@/stores/audit";
import { useAuthStore } from "@/stores/auth";

export function useAudit() {
  const record = useAuditStore((s) => s.record);
  const user = useAuthStore((s) => s.user);
  return useCallback(
    (action: string, target?: string, result: "success" | "denied" | "error" = "success") => {
      record({ actor: user?.username ?? "anonymous", action, target, result });
    },
    [record, user],
  );
}
