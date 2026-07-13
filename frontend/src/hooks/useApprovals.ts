import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  decideApproval,
  listApprovals,
  markApprovalExecuted,
} from "@/services/approvals";
import type { ApprovalStatus } from "@/types/api";
import { useNotificationsStore } from "@/stores/notifications";
import { useAudit } from "./useAudit";

export const approvalKeys = {
  all: ["approvals"] as const,
  filtered: (status?: ApprovalStatus, investigationId?: string) =>
    ["approvals", status ?? "any", investigationId ?? "any"] as const,
};

export function useApprovals(status?: ApprovalStatus, investigationId?: string) {
  return useQuery({
    queryKey: approvalKeys.filtered(status, investigationId),
    queryFn: () => listApprovals({ status, investigation_id: investigationId }),
    refetchInterval: 15_000,
  });
}

export function useDecideApproval() {
  const qc = useQueryClient();
  const push = useNotificationsStore((s) => s.push);
  const audit = useAudit();
  return useMutation({
    mutationFn: ({ id, approve, note }: { id: string; approve: boolean; note: string }) =>
      decideApproval(id, approve, note),
    onSuccess: (req) => {
      qc.invalidateQueries({ queryKey: approvalKeys.all });
      audit(`approval.${req.status}`, req.approval_id, "success");
      push({
        level: req.status === "approved" ? "warning" : "info",
        title: `Action ${req.status}`,
        message: req.step.action,
      });
    },
    onError: () => audit("approval.decision", undefined, "error"),
  });
}

export function useMarkExecuted() {
  const qc = useQueryClient();
  const push = useNotificationsStore((s) => s.push);
  const audit = useAudit();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      markApprovalExecuted(id, note),
    onSuccess: (req) => {
      qc.invalidateQueries({ queryKey: approvalKeys.all });
      audit("approval.executed", req.approval_id, "success");
      push({ level: "info", title: "Action executed", message: req.step.action });
    },
    onError: () => audit("approval.executed", undefined, "error"),
  });
}
