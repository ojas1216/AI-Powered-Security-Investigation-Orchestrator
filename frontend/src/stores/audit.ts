import { create } from "zustand";

export interface AuditEntry {
  id: string;
  ts: number;
  actor: string;
  action: string;
  target?: string;
  result: "success" | "denied" | "error";
}

interface AuditState {
  entries: AuditEntry[];
  record: (e: Omit<AuditEntry, "id" | "ts">) => void;
}

/**
 * Client-side audit trail for UX traceability (who clicked what). Authoritative
 * audit logging is server-side (backend audit_log table); this complements it.
 */
export const useAuditStore = create<AuditState>((set) => ({
  entries: [],
  record: (e) =>
    set((s) => ({
      entries: [{ ...e, id: crypto.randomUUID(), ts: Date.now() }, ...s.entries].slice(0, 500),
    })),
}));
