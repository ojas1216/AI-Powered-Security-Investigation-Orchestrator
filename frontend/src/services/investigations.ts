import { http } from "./http";
import type { InvestigationPackage } from "@/types/api";

/** Raw alert payloads accepted by POST /alerts/ingest (source-shaped). */
export type RawAlert = Record<string, unknown> & { source: string };

export async function listInvestigations(): Promise<InvestigationPackage[]> {
  const { data } = await http.get<InvestigationPackage[]>("/investigations");
  return data;
}

export async function getInvestigation(id: string): Promise<InvestigationPackage> {
  const { data } = await http.get<InvestigationPackage>(`/investigations/${id}`);
  return data;
}

export async function ingestAlert(alert: RawAlert): Promise<InvestigationPackage> {
  const { data } = await http.post<InvestigationPackage>("/alerts/ingest", alert);
  return data;
}
