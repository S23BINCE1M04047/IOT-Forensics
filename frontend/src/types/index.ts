export type AnalysisStatus = "uploaded" | "queued" | "running" | "done" | "error";

export type Priority = "P1" | "P2" | "P3" | "P4";

export interface AnalysisRunInfo {
  ruleset_version: string;
  baseline_id: number | null;
  baseline_name: string | null;
  finding_count: number;
}


export interface ApiErrorBody {
  code: string;
  message: string;
}

export interface Envelope<T> {
  ok: boolean;
  data: T | null;
  error: ApiErrorBody | null;
}

export interface Capture {
  file_id: string;
  original_filename: string;
  size_bytes: number;
  sha256: string;
  uploaded_at: string;
  analyzed_at: string | null;
  tool_version: string;
  status: AnalysisStatus;
  analyst_note: string | null;
  analyzed_sha256: string | null;
  integrity_ok: boolean | null;
}

export interface StatusInfo {
  file_id: string;
  status: AnalysisStatus;
  packets_parsed: number;
  error_message: string | null;
  integrity_ok: boolean | null;
  integrity_warning: string | null;
}

export interface ProtocolCount {
  protocol: string;
  packets: number;
}

export interface MinuteBucket {
  ts: number;
  minute: string;
  packets: number;
}

export interface TopTalker {
  src_ip: string;
  dst_ip: string;
  packets: number;
  bytes: number;
}

export interface Summary {
  capture: Capture;
  total_packets: number;
  total_connections: number;
  unique_src_ips: number;
  unique_dst_ips: number;
  first_packet_utc: string | null;
  last_packet_utc: string | null;
  protocols: ProtocolCount[];
  packets_per_minute: MinuteBucket[];
  top_talkers: TopTalker[];
  priority_counts: Record<Priority, number>;
  findings_total: number;
  analysis_run: AnalysisRunInfo | null;
}

export interface PacketRow {
  packet_number: number;
  ts: number;
  ts_utc: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  ttl: number | null;
  flags: string | null;
  dns_query: string | null;
  dns_qtype: string | null;
  dns_answers: string | null;
  http_method: string | null;
  http_host: string | null;
  http_uri: string | null;
  http_user_agent: string | null;
  payload_preview: string | null;
  stream_id: string | null;
}

export interface PacketPage {
  items: PacketRow[];
  total: number;
  page: number;
  page_size: number;
}

export interface Finding {
  finding_id: number;
  capture_id: string;
  priority: Priority;
  original_priority: Priority;
  overridden: boolean;
  rule_id: string;
  reason: string;
  confidence: number;
  confidence_breakdown: Record<string, number>;
  packet_refs: number[];
  packet_ref_count: number;
  ts_first: number;
  ts_first_utc: string;
  ts_last: number;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: string;
  stream_id: string | null;
  details: Record<string, unknown>;
  analyst_note: string | null;
  overridden_at: string | null;
  overridden_by: string | null;
  created_at: string | null;
}

export interface FindingPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingDetail extends Finding {
  packets: PacketRow[];
  packets_shown: number;
  wireshark_filter: string;
}

export interface Baseline {
  id: number;
  name: string;
  capture_id: string;
  created_at: string;
  packet_count: number;
}