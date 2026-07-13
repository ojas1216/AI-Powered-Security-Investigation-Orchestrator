import { http } from "./http";
import type { ApprovalRequest, ApprovalStatus } from "@/types/api";

export async function listApprovals(params?: {
  status?: ApprovalStatus;
  investigation_id?: string;
}): Promise<ApprovalRequest[]> {
  const { data } = await http.get<ApprovalRequest[]>("/approvals", { params });
  return data;
}

export async function decideApproval(
  approvalId: string,
  approve: boolean,
  note: string,
): Promise<ApprovalRequest> {
  const { data } = await http.post<ApprovalRequest>(
    `/approvals/${encodeURIComponent(approvalId)}/decision`,
    { approve, note },
  );
  return data;
}

export async function markApprovalExecuted(
  approvalId: string,
  note: string,
): Promise<ApprovalRequest> {
  const { data } = await http.post<ApprovalRequest>(
    `/approvals/${encodeURIComponent(approvalId)}/executed`,
    { note },
  );
  return data;
}
