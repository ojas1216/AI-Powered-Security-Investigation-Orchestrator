// Mirrors backend Pydantic schemas (app/schemas/investigation.py).
export type Verdict = "malicious" | "suspicious" | "benign" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface EnrichedIOC {
  ioc: { type: string; value: string; context?: string | null };
  verdict: Verdict;
  confidence: number;
  sightings: number;
}

export interface TimelineEvent {
  timestamp: string;
  actor?: string | null;
  action: string;
  detail?: string | null;
  source?: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface RiskBreakdown {
  score: number;
  severity: Severity;
  factors: Record<string, number>;
  rationale: string[];
}

export interface InvestigationPackage {
  investigation_id: string;
  tenant: string;
  status: string;
  overall_verdict: Verdict;
  risk: RiskBreakdown | null;
  iocs: EnrichedIOC[];
  timeline: TimelineEvent[];
  mitre: MitreTechnique[];
  affected_hosts: string[];
  affected_users: string[];
  executive_summary: string;
  analyst_report: string;
}
