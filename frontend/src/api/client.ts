import type {
  Baseline, Capture, Envelope, Finding, FindingDetail, FindingPage, PacketPage, Priority, StatusInfo, Summary,
} from "../types";

const BASE: string = import.meta.env.VITE_API_BASE ?? "/api";

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, init);
  } catch {
    throw new ApiError("network", "Cannot reach the backend. Is it running on port 8000?", 0);
  }
  let body: Envelope<T> | null = null;
  try {
    body = (await res.json()) as Envelope<T>;
  } catch {
    body = null;
  }
  if (!body || !body.ok || body.data === null) {
    throw new ApiError(body?.error?.code ?? "http_error", body?.error?.message ?? `HTTP ${res.status}`, res.status);
  }
  return body.data;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export function uploadPcap(file: File, analystNote?: string): Promise<Capture> {
  const form = new FormData();
  form.append("file", file);
  if (analystNote) form.append("analyst_note", analystNote);
  return request<Capture>("/upload", { method: "POST", body: form });
}

export const startAnalysis = (fileId: string, baselineId?: number | null): Promise<StatusInfo> =>
  request<StatusInfo>(`/analyze/${fileId}${baselineId ? `?baseline_id=${baselineId}` : ""}`, { method: "POST" });

export const getStatus = (fileId: string): Promise<StatusInfo> => request<StatusInfo>(`/status/${fileId}`);

export const getSummary = (fileId: string): Promise<Summary> => request<Summary>(`/summary/${fileId}`);

export interface PacketQuery {
  page: number;
  pageSize: number;
  q: string;
  protocol: string;
}

export function getPackets(fileId: string, p: PacketQuery): Promise<PacketPage> {
  const qs = new URLSearchParams({ page: String(p.page), page_size: String(p.pageSize) });
  if (p.q) qs.set("q", p.q);
  if (p.protocol) qs.set("protocol", p.protocol);
  return request<PacketPage>(`/packets/${fileId}?${qs.toString()}`);
}

export interface FindingQuery {
  page: number;
  pageSize: number;
  priorities: Priority[];
  protocol: string;
  ip: string;
  from?: number;
  to?: number;
  sortBy: string;
  sortDir: "asc" | "desc";
}

export function getFindings(fileId: string, f: FindingQuery): Promise<FindingPage> {
  const qs = new URLSearchParams({
    page: String(f.page), page_size: String(f.pageSize), sort_by: f.sortBy, sort_dir: f.sortDir,
  });
  if (f.priorities.length > 0) qs.set("priority", f.priorities.join(","));
  if (f.protocol) qs.set("protocol", f.protocol);
  if (f.ip) qs.set("ip", f.ip);
  if (f.from !== undefined) qs.set("ts_from", String(f.from));
  if (f.to !== undefined) qs.set("ts_to", String(f.to));
  return request<FindingPage>(`/findings/${fileId}?${qs.toString()}`);
}

export const getFinding = (id: number): Promise<FindingDetail> => request<FindingDetail>(`/findings/${id}`);

export interface OverrideBody {
  priority: Priority | null;
  analyst_note: string;
  analyst: string;
}

export const patchFinding = (id: number, body: OverrideBody): Promise<Finding> =>
  request<Finding>(`/findings/${id}`, { method: "PATCH", headers: JSON_HEADERS, body: JSON.stringify(body) });

export const listBaselines = (): Promise<Baseline[]> => request<Baseline[]>("/baselines");

export const createBaseline = (name: string, captureId: string): Promise<Baseline> =>
  request<Baseline>("/baselines", {
    method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ name, capture_id: captureId }),
  });