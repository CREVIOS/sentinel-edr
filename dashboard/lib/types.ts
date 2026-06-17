export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Process { pid?: number; ppid?: number; name?: string; exe?: string; cmdline?: string; uid?: number; user?: string; parent?: string; lineage?: string; container?: string; }
export interface FileInfo { path?: string; op?: string; size?: number; hash?: string; }
export interface NetInfo { direction?: string; proto?: string; remote?: string; domain?: string; url?: string; category?: string; bytes_out?: number; bytes_in?: number; blocked?: boolean; }
export interface UsbInfo { action?: string; vendor?: string; product?: string; serial?: string; mount?: string; size_gb?: number; }
export interface AuthInfo { method?: string; source_ip?: string; tty?: string; result?: string; }
export interface DlpInfo { classifier?: string; channel?: string; matches?: number; sample?: string; verdict?: string; }

export interface Event {
  id: string; agent_id: string; hostname: string; ts: string; category: string; action: string;
  severity: Severity; user?: string; message?: string;
  process?: Process; file?: FileInfo; network?: NetInfo; usb?: UsbInfo; auth?: AuthInfo; dlp?: DlpInfo; labels?: string[];
}
export interface Agent {
  id: string; hostname: string; os: string; kernel: string; arch: string; ip: string; mac: string;
  version: string; status: "online" | "offline" | "isolated"; labels?: string[];
  enrolled_at: string; last_seen: string; event_count: number;
}
export interface Detection {
  id: string; ts: string; rule_id: string; rule_name: string; severity: Severity; category: string;
  agent_id: string; hostname: string; user?: string; summary: string; mitre?: string[]; tactic?: string;
  status: "open" | "acknowledged" | "closed"; event_ids?: string[]; engine: string; assigned_to?: string;
}
export interface ResponseAction {
  id: string; ts: string; type: string; agent_id: string; hostname: string; target: Record<string, unknown>;
  reason: string; issued_by: string; detection_id?: string; status: string; result?: string; automated: boolean;
}
export interface TriageResult {
  summary: string; assessment: string; recommended_actions: string[];
  confidence: string; model: string; generated_at: string; cached: boolean;
}
export interface Rule { ID: string; Title: string; Severity: string; Category: string; Tactic: string; Description: string; AutoRespond: string; MITRE: string[] | null; Enabled: boolean; }

export type CaseStatus = "open" | "investigating" | "contained" | "closed";
export interface CaseNote { ts: string; author: string; body: string; }
export interface Case {
  id: string; title: string; severity: Severity; status: CaseStatus; assigned_to?: string;
  agent_id?: string; hostname?: string; detection_ids: string[]; mitre?: string[];
  notes?: CaseNote[]; created_at: string; updated_at: string; created_by?: string;
}
export interface CaseDetail extends Case { detections: Detection[]; }
export interface Suppression {
  id: string; rule_id: string; field: string; op: string; value: string;
  reason?: string; created_by?: string; created_at: string; expires?: string; hits: number;
}
export interface Overview {
  counts: Record<string, number>;
  severity: Record<string, number>;
  events_by_category: Record<string, number>;
  timeline: { hour: string; count: number }[];
  top_mitre: { tactic: string; count: number }[];
}
