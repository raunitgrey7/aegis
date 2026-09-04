// Type definitions mirroring the Aegis API contract (docs/API_CONTRACT.md).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Role = "admin" | "analyst" | "viewer" | "ingestor";

export interface TokenResponse {
  access_token: string;
  token_type: string;
  role: Role;
  expires_in_minutes: number;
}

export interface Me {
  username: string;
  role: Role;
  tenant: string;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  status: string;
  affected_users: string[];
  affected_hosts: string[];
  external_ips: string[];
  techniques: string[];
  phases: string[];
  first_event_at: string;
  last_event_at: string;
  detection_count: number;
  tags: string[];
}

export interface TopIncident {
  incident_id: string;
  title: string;
  severity: Severity;
  risk: number;
  hosts: string[];
  users: string[];
  phases: string[];
  status: string;
  created_at: string;
}

export interface Overview {
  threat_level: "CRITICAL" | "HIGH" | "ELEVATED" | "LOW";
  active_incidents: number;
  critical: number;
  high: number;
  suspicious_users: number;
  affected_hosts: number;
  events_ingested: number;
  events_deduplicated: number;
  detections: number;
  last_event_at: string | null;
  uptime_seconds: number;
  graph: { nodes: number; edges: number; by_kind: Record<string, number> };
  threat_intel: { ips: number; domains: number; hashes: number; urls: number; cidrs: number };
  detector: {
    events_processed: number;
    avg_latency_us: number;
    rules_loaded: number;
    [k: string]: unknown;
  };
  top_incidents: TopIncident[];
  severity_distribution: Record<string, number>;
  phase_distribution: { phase: string; label: string; count: number }[];
  tactic_coverage: { tactic: string; label: string; count: number }[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  layer: number;
  risk: number;
  attributes: Record<string, unknown>;
  evidence_event_ids: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  timestamp: string | null;
  phase: string | null;
  techniques: string[];
  evidence_event_ids: string[];
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface PhaseEvidence {
  phase: string;
  label: string;
  present: boolean;
  techniques: string[];
  detection_ids: string[];
  first_seen: string | null;
}

export interface Detection {
  detection_id: string;
  kind: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  score: number;
  confidence: number;
  techniques: string[];
  phase: string | null;
  timestamp: string;
  entities: Record<string, string>;
  evidence_event_ids: string[];
  details: Record<string, unknown>;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  action: string;
  outcome: string | null;
  host: string | null;
  user: string | null;
  process_name: string | null;
  parent_process_name: string | null;
  command_line: string | null;
  file_path: string | null;
  file_size: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  domain: string | null;
  bytes_out: number | null;
  geo_country: string | null;
  privilege: string | null;
  message: string | null;
  [k: string]: unknown;
}

export interface Incident {
  incident_id: string;
  title: string;
  status: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  created_at: string;
  first_event_at: string;
  last_event_at: string;
  affected_users: string[];
  affected_hosts: string[];
  external_ips: string[];
  domains: string[];
  techniques: string[];
  phases: PhaseEvidence[];
  detections: Detection[];
  event_ids: string[];
  graph: AttackGraph;
  score_breakdown: Record<string, number>;
  summary: string;
  tags: string[];
  events: SecurityEvent[];
  critical_path: string[];
}

export interface AgentFinding {
  agent: string;
  headline: string;
  detail: string;
  confidence: number;
  evidence_event_ids: string[];
}

export interface TimelineItem {
  time: string;
  event_id: string;
  summary: string;
  phase: string | null;
  techniques: string[];
}

export interface Grounding {
  evidence_total: number;
  evidence_cited: number;
  fabricated_ids: string[];
  coverage: number;
  fidelity: number;
  grounded: boolean;
}

export interface ClaimVerification {
  method: string;
  claims: { kind: string; value: string; supported: boolean; note: string }[];
  total: number;
  supported: number;
  unsupported: number;
  unsupported_claims: { kind: string; value: string; supported: boolean; note: string }[];
  fidelity: number;
  verified: boolean;
}

export interface Verification {
  reference_integrity: { passed: boolean; cited: number; fabricated: number; label: string; proves: string };
  semantic_check: { passed: boolean; supported: number; total: number; fidelity: number; label: string; proves: string };
  not_verified: string;
  narrative_source: string;
}

export interface InvestigationReport {
  incident_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  generated_at: string;
  llm_used: boolean;
  model: string | null;
  summary: string;
  attack_narrative: string;
  affected_users: string[];
  affected_hosts: string[];
  external_ips: string[];
  phases_present: string[];
  techniques: { id: string; name: string; tactic: string | null; url: string | null }[];
  timeline: TimelineItem[];
  agent_findings: AgentFinding[];
  recommended_actions: string[];
  injection_warnings: { event_id: string; field: string; value: string }[];
  grounding: Grounding;
  claim_verification?: ClaimVerification;
  verification?: Verification;
  latency_ms: number;
}

export interface CopilotResponse {
  question: string;
  answer: string;
  evidence: { event_id: string; time: string; summary: string }[];
  llm_used: boolean;
  grounding: Grounding;
  claim_verification?: ClaimVerification;
  verification?: Verification;
}

export interface ThreatMapNode {
  type: string;
  value: string;
  incident: string;
  risk: number;
  known_malicious: boolean;
  threat: string | null;
  country: string | null;
  hosts: string[];
}

export interface ThreatOrigin {
  country: string;
  incidents: number;
  max_risk: number;
  users: string[];
}

export interface ThreatMapResponse {
  nodes: ThreatMapNode[];
  origins: ThreatOrigin[];
  hq: { country: string };
}

export interface RuleInfo {
  id: string;
  title: string;
  kind: string;
  severity: Severity;
  score: number;
  techniques: string[];
  phase: string | null;
  description: string;
  group_by: string[];
  window_seconds: number;
  source_file: string;
  fired: number;
}

export interface MitreCoverage {
  techniques_total: number;
  techniques_covered: number;
  tactics: Record<
    string,
    {
      label: string;
      total: number;
      covered: number;
      techniques: { id: string; name: string; covered: boolean }[];
    }
  >;
}
