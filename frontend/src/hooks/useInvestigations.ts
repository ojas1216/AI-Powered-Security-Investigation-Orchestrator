import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getInvestigation,
  ingestAlert,
  listInvestigations,
  type RawAlert,
} from "@/services/investigations";
import { useNotificationsStore } from "@/stores/notifications";
import { useAudit } from "./useAudit";

export const investigationKeys = {
  all: ["investigations"] as const,
  detail: (id: string) => ["investigations", id] as const,
};

export function useInvestigations() {
  return useQuery({
    queryKey: investigationKeys.all,
    queryFn: listInvestigations,
    refetchInterval: 15_000,
  });
}

export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: investigationKeys.detail(id ?? ""),
    queryFn: () => getInvestigation(id as string),
    enabled: !!id,
  });
}

export function useIngestAlert() {
  const qc = useQueryClient();
  const push = useNotificationsStore((s) => s.push);
  const audit = useAudit();
  return useMutation({
    mutationFn: (alert: RawAlert) => ingestAlert(alert),
    onSuccess: (pkg) => {
      qc.invalidateQueries({ queryKey: investigationKeys.all });
      qc.setQueryData(investigationKeys.detail(pkg.investigation_id), pkg);
      audit("alert.ingest", pkg.investigation_id, "success");
      push({
        level: pkg.overall_verdict === "malicious" ? "critical" : "info",
        title: `Investigation complete — ${pkg.overall_verdict}`,
        message: `${pkg.alert.title} · risk ${pkg.risk?.score ?? "n/a"}`,
      });
    },
    onError: () => audit("alert.ingest", undefined, "error"),
  });
}
