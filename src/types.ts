// ── Core engagement types ──

export interface Finding {
  id: string;
  host: string;
  vulnerability: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss: number | null;
  status: "confirmed" | "potential" | "exploited" | "false_positive";
  evidence_file: string | null;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface Service {
  port: number;
  proto: "tcp" | "udp";
  service: string;
  version: string;
  notes: string;
}

export interface Host {
  ip: string;
  hostname: string;
  os: string;
  first_seen: string;
  updated_at: string;
  services: Service[];
  enumeration: string;
  vulnerabilities: string;
  exploitation: string;
  post_exploitation: string;
  credentials: string;
  key_commands: string;
}

export interface Credential {
  id: string;
  source: string;
  username: string;
  password_or_hash: string;
  cred_type: "password" | "hash" | "token" | "key" | "certificate";
  access_level: string;
  verified: boolean;
  created_at: string;
}

export interface DeadEnd {
  timestamp: string;
  technique: string;
  target: string;
  reason: string;
}

export interface Todo {
  id: string;
  description: string;
  priority: "high" | "medium" | "low";
  status: "pending" | "completed";
  created_at: string;
  completed_at: string | null;
}

export interface EvidenceEntry {
  filename: string;
  description: string;
  related_finding_id: string | null;
  created_at: string;
}

export interface CommandEntry {
  id: string;
  command: string;
  tool: string;
  target: string;
  started_at: string;
  finished_at: string;
  duration_seconds: number | null;
  exit_code: number | null;
  evidence_file: string | null;
  parsed: boolean;
  source: "mcp" | "cli" | "nyx-log";
}

export interface AttackPathStep {
  step: number;
  description: string;
  timestamp: string;
}

export interface EngagementMetadata {
  id: string;
  target: string;
  scope: string[];
  rules_of_engagement: string;
  status: "active" | "paused" | "completed";
  created_at: string;
  updated_at: string;
  executive_summary: string;
  attack_path: AttackPathStep[];
  findings: Finding[];
  hosts: Host[];
  credentials: Credential[];
  dead_ends: DeadEnd[];
  todos: Todo[];
  evidence_index: EvidenceEntry[];
  command_log: CommandEntry[];
  schema_version: number;
}

// ── Global state types ──

export interface AppState {
  current_engagement_id: string | null;
}

export interface IndexEntry {
  id: string;
  target: string;
  status: "active" | "paused" | "completed";
  created_at: string;
  updated_at: string;
  finding_count: number;
  host_count: number;
  credential_count: number;
  command_count: number;
}

export interface GlobalConfig {
  data_dir: string;
  auto_timestamp: boolean;
  finding_id_prefix: string;
  todo_id_prefix: string;
}

// ── Parser types ──

export interface HostData {
  ip: string;
  hostname?: string;
  os?: string;
  services?: ServiceData[];
}

export interface ServiceData {
  port: number;
  proto: "tcp" | "udp";
  service?: string;
  version?: string;
  notes?: string;
}

export interface FindingData {
  host: string;
  vulnerability: string;
  severity: Finding["severity"];
  cvss?: number;
  status?: Finding["status"];
  notes?: string;
}

export interface ParseResult {
  hosts: HostData[];
  findings: FindingData[];
  raw_text?: string;
}

export interface ToolParser {
  name: string;
  parse(content: string): Promise<ParseResult>;
}
