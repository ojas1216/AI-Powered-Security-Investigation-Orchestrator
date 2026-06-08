/**
 * TypeScript mirror of the backend Pydantic schemas
 * (backend/app/schemas/*). Keep in sync with the API contract.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "malicious" | "suspicious" | "benign" | "unknown";
export type InvestigationStatus = "queued" | "running" | "complete" | "failed";
export type IOCType =
  | "url"
  | "domain"
  | "ipv4"
  | "ipv6"
  | "sha256"
  | "sha1"
  | "md5"
  | "email"
  | "filename"
  | "registry_key"
  | "mutex";
export type SourceProduct =
  | "splunk"
  | "elastic"
  | "sentinel"
  | "qradar"
  | "wazuh"
  | "chronicle"
  | "generic";

export interface IOC {
  type: IOCType;
  value: string;
  first_seen?: string | null;
  context?: string | null;
}

export interface SourceVerdict {
  source: string;
  verdict: Verdict;
  score: number;
  detail?: string | null;
  raw_ref?: string | null;
}

export interface EnrichedIOC {
  ioc: IOC;
  verdict: Verdict;
  confidence: number;
  sources: SourceVerdict[];
  threat_actors: string[];
  sightings: number;
}

export interface Alert {
  source: SourceProduct;
  source_alert_id: string;
  title: string;
  description: string;
  severity: Severity;
  created_at: string;
  src_ips: string[];
  dst_ips: string[];
  users: string[];
  hosts: string[];
  raw_text: string;
  extra: Record<string, unknown>;
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

export interface Evidence {
  kind: string;
  label: string;
  sha256: string;
  uri: string;
  collected_at: string;
}

export interface RiskBreakdown {
  score: number;
  severity: Severity;
  factors: Record<string, number>;
  rationale: string[];
}

export interface PlaybookStep {
  phase: string;
  action: string;
  rationale: string;
  requires_approval: boolean;
}

export interface TicketRef {
  system: string;
  ticket_id: string;
  url?: string | null;
}

export interface InvestigationPackage {
  investigation_id: string;
  tenant: string;
  status: InvestigationStatus;
  alert: Alert;
  overall_verdict: Verdict;
  risk: RiskBreakdown | null;
  iocs: EnrichedIOC[];
  timeline: TimelineEvent[];
  mitre: MitreTechnique[];
  evidence: Evidence[];
  affected_hosts: string[];
  affected_users: string[];
  playbook: PlaybookStep[];
  tickets: TicketRef[];
  executive_summary: string;
  analyst_report: string;
  created_at: string;
  completed_at?: string | null;
}

export interface CopilotAnswer {
  answer: string;
  grounded_on: string[];
}

export interface ApiError {
  error: { code: string; message: string };
}
