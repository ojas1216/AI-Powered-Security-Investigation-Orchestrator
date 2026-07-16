import { http } from "./http";
import type {
  AgentInfo,
  AgentResult,
  AttackTechnique,
  CampaignCluster,
  CaseSearchHit,
  CveRecord,
  DatasetStatus,
  ExecutiveSummary,
  GeneratedRule,
  InvestigationPackage,
} from "@/types/api";

// ── Executive intelligence ───────────────────────────────────────────────────

export async function executiveSummary(windowDays = 30): Promise<ExecutiveSummary> {
  const { data } = await http.get<ExecutiveSummary>("/executive/summary", {
    params: { window_days: windowDays },
  });
  return data;
}

// ── Multi-format detection export ────────────────────────────────────────────

export async function exportDetections(investigationId: string): Promise<GeneratedRule[]> {
  const { data } = await http.get<GeneratedRule[]>(
    `/detections/export/${encodeURIComponent(investigationId)}`,
  );
  return data;
}

// ── Campaigns ────────────────────────────────────────────────────────────────

export async function listCampaigns(): Promise<CampaignCluster[]> {
  const { data } = await http.get<CampaignCluster[]>("/campaigns");
  return data;
}

// ── Specialist agents ────────────────────────────────────────────────────────

export async function listAgents(): Promise<AgentInfo[]> {
  const { data } = await http.get<AgentInfo[]>("/agents");
  return data;
}

export async function runAgent(
  name: string,
  payload: Record<string, unknown>,
): Promise<AgentResult> {
  const { data } = await http.post<AgentResult>(
    `/agents/${encodeURIComponent(name)}/run`,
    { payload },
  );
  return data;
}

// ── Natural-language case search ─────────────────────────────────────────────

export async function searchCases(
  query: string,
  limit = 10,
): Promise<CaseSearchHit[]> {
  const { data } = await http.post<CaseSearchHit[]>("/search/cases", { query, limit });
  return data;
}

// ── Offline knowledge base ───────────────────────────────────────────────────

export async function offlineStatus(): Promise<DatasetStatus[]> {
  const { data } = await http.get<DatasetStatus[]>("/offline/status");
  return data;
}

export async function lookupCve(cveId: string): Promise<CveRecord> {
  const { data } = await http.get<CveRecord>(`/offline/cve/${encodeURIComponent(cveId)}`);
  return data;
}

export async function lookupTechnique(id: string): Promise<AttackTechnique> {
  const { data } = await http.get<AttackTechnique>(
    `/offline/attack/${encodeURIComponent(id)}`,
  );
  return data;
}

// ── File / artifact ingestion ────────────────────────────────────────────────

/** Read a File as base64 (strips the data: URL prefix). */
export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result);
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

export async function ingestFile(
  filename: string,
  contentB64: string,
): Promise<InvestigationPackage> {
  const { data } = await http.post<InvestigationPackage>("/alerts/ingest-file", {
    filename,
    content_b64: contentB64,
  });
  return data;
}
