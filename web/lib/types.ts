// Domain types mirror PRD section 6 (PostgreSQL + ClickHouse schemas).

export type Role = "Admin" | "SecOps Analyst" | "Auditor";

export type NodeStatus = "ONLINE" | "WARN" | "OFFLINE";
export type SyncStatus = "IN_SYNC" | "PENDING_UPDATE";

export interface EdgeNode {
  id: string;
  node_name: string;
  hostname: string;
  ip_address: string;
  proxy: "Caddy" | "Envoy" | "SPOA" | "Standalone";
  version: string;
  crs_version: string;
  status: NodeStatus;
  current_config_version: number;
  sync_status: SyncStatus;
  cpu: number; // %
  memory: number; // %
  rps: number;
  latency_ms: number;
  last_heartbeat: string;
  region: string;
  geo: [number, number]; // lon, lat
  history: { t: number; rps: number; latency: number; cpu: number }[];
}

export interface Site {
  id: string;
  name: string;
  domain_name: string;
  paranoia_level: 1 | 2 | 3 | 4;
  inbound_threshold: number;
  outbound_threshold: number;
  crs_categories: Record<string, boolean>;
  updated_at: string;
}

export interface CustomRule {
  id: string;
  rule_id: number;
  site_id: string | null;
  name: string;
  seclang_raw: string;
  is_active: boolean;
  created_by: string;
  updated_at: string;
}

export interface RuleException {
  id: string;
  site_id: string;
  rule_id: number;
  path_pattern: string;
  parameter_name: string | null;
  reason: string;
  created_by: string;
  created_at: string;
}

export type Action = "DENY" | "LOG" | "ALLOW";

export interface AuditLog {
  id: string;
  timestamp: string;
  transaction_id: string;
  node_id: string;
  site_id: string;
  host: string;
  client_ip: string;
  client_port: number;
  country_code: string;
  asn: number;
  http_method: string;
  uri: string;
  http_version: string;
  response_status: number;
  action_taken: Action;
  matched_rule_ids: number[];
  matched_messages: string[];
  matched_data: string[];
  matched_vars: string[];
  severity: Severity;
  request_headers: Record<string, string>;
  request_body: string;
  latency_us: number;
  campaign_id?: string;
}

export type Severity = "CRITICAL" | "ERROR" | "WARNING" | "NOTICE";

export type StageKey = "RECON" | "WEAPON" | "DELIVERY" | "EXPLOIT" | "INSTALL" | "C2" | "OBJECTIVES";
export type RuleCategory = "SQLI" | "XSS" | "RCE" | "LFI" | "SCANNER" | "PROTOCOL" | "LEAKAGE";
export type Outcome = "BLOCKED" | "DETECTED" | "POSSIBLY_SUCCESSFUL";
export type CampaignStatus = "ACTIVE" | "CONTAINED" | "CLOSED" | "FALSE_POSITIVE";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export interface AttackEvent {
  id: string;
  timestamp: number; // epoch ms
  transaction_id: string;
  campaign_id: string;
  node_id: string;
  site_id: string;
  host: string;
  client_ip: string;
  country_code: string;
  asn: number;
  geo: [number, number];
  method: string;
  uri: string;
  rule_id: number;
  rule_category: RuleCategory;
  killchain_stage: StageKey;
  severity: Severity;
  outcome: Outcome;
  response_status: number;
}

export interface Campaign {
  id: string;
  actor_key: string;
  actor_mode: "IP" | "CIDR24" | "ASN" | "FINGERPRINT";
  country_code: string;
  asn: number;
  as_name: string;
  geo: [number, number];
  correlation_confidence: Confidence;
  first_seen: number;
  last_seen: number;
  highest_stage: StageKey;
  stages: StageKey[];
  risk_score: number;
  event_count: number;
  status: CampaignStatus;
  assignee: string | null;
  notes: { author: string; at: number; text: string }[];
  targets: string[];
  possibly_successful: number;
}

export interface IpListEntry {
  id: string;
  cidr: string;
  list: "block" | "allow";
  source: string; // "manual" | feed name
  reason: string;
  expires_at: string | null;
  created_by: string;
  created_at: string;
}

export interface ThreatFeed {
  id: string;
  name: string;
  url: string;
  format: "text" | "csv";
  interval_minutes: number;
  last_pulled: string | null;
  entries: number;
  status: "OK" | "ERROR" | "NEVER";
  error?: string;
}

export interface AuditTrailEntry {
  id: string;
  at: string;
  actor: string;
  role: Role;
  action: string;
  target: string;
  source_ip: string;
  target_nodes: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  mfa: boolean;
  last_login: string | null;
}

export interface KillchainMapping {
  id: string;
  rule_id_from: number;
  rule_id_to: number;
  tag: string | null;
  rule_category: RuleCategory;
  killchain_stage: StageKey;
  mitre_technique: string | null;
}

export interface CorrelationSettings {
  site_id: string;
  actor_key_mode: "IP" | "CIDR24" | "ASN" | "FINGERPRINT";
  idle_timeout_minutes: number;
  min_events_to_open: number;
}
