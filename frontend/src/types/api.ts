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

export interface EDRHit {
  ioc: IOC;
  host: string;
  user?: string | null;
  process?: string | null;
  observed_at: string;
  detail: string;
}

export interface DetectionMatch {
  rule_id: string;
  title: string;
  severity: Severity;
  techniques: MitreTechnique[];
  matched_fields: Record<string, string>;
  tags: string[];
}

export interface AgentTraceStep {
  step: number;
  iteration: number;
  phase: "plan" | "act" | "observe" | "finalize";
  action: string;
  reason: string;
  outcome: string;
  ok: boolean;
  duration_ms: number;
  started_at: string;
}

export interface RelatedCase {
  investigation_id: string;
  title: string;
  verdict: Verdict;
  risk_score: number;
  similarity: number;
  shared_iocs: string[];
  shared_techniques: string[];
}

export type ApprovalStatus = "pending" | "approved" | "rejected" | "executed" | "expired";

export interface ApprovalRequest {
  approval_id: string;
  tenant: string;
  investigation_id: string;
  step: PlaybookStep;
  status: ApprovalStatus;
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decided_by?: string | null;
  decided_at?: string | null;
  decision_note?: string | null;
  executed_by?: string | null;
  executed_at?: string | null;
  execution_note?: string | null;
}

export interface BusinessImpact {
  level: Severity;
  blast_radius_hosts: number;
  blast_radius_users: number;
  affected_asset_classes: string[];
  estimated_cost_band: string;
  downtime_risk: string;
  rationale: string[];
}

export interface RootCause {
  initial_vector: string;
  initial_event: TimelineEvent | null;
  kill_chain: string[];
  narrative: string;
}

export interface AgentInfo {
  name: string;
  description: string;
  input_hint: Record<string, string>;
}

export interface AgentResult {
  agent: string;
  ok: boolean;
  summary: string;
  data: Record<string, unknown>;
}

export interface CaseSearchHit {
  investigation_id: string;
  title: string;
  verdict: Verdict;
  risk_score: number;
  score: number;
  snippet: string;
}

export interface CveRecord {
  cve_id: string;
  cvss: number;
  severity: string;
  summary: string;
  references: string[];
  cwe: string;
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface DatasetStatus {
  name: string;
  records: number;
  loaded_from: string;
  source_url: string;
  version: string;
  refreshed_at: string | null;
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
  approval_ids: string[];
  tickets: TicketRef[];
  executive_summary: string;
  analyst_report: string;
  detections: DetectionMatch[];
  agent_trace: AgentTraceStep[];
  related_investigations: RelatedCase[];
  business_impact: BusinessImpact | null;
  root_cause: RootCause | null;
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
