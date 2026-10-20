import { useEffect, useState } from "react";
import { errorMessage, getFindings } from "../api/client";
import type { FindingPage, Priority } from "../types";
import PriorityBadge, { PRIORITY_STYLES } from "./PriorityBadge";

interface Props {
  fileId: string;
  protocols: string[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  refreshKey: number;
}

const PAGE_SIZE = 50;
const ALL: Priority[] = ["P1", "P2", "P3", "P4"];
const COLUMNS: { key: string; label: string }[] = [
  { key: "timestamp", label: "Timestamp" }, { key: "src", label: "Src" }, { key: "dst", label: "Dst" },
  { key: "protocol", label: "Protocol" }, { key: "priority", label: "Priority" }, { key: "reason", label: "Reason" },
  { key: "confidence", label: "Confidence" }, { key: "packet_refs", label: "Packet Refs" },
];

function toEpoch(local: string): number | undefined {
  if (!local) return undefined;
  const ms = Date.parse(local.length === 16 ? `${local}:00Z` : `${local}Z`); // inputs are interpreted as UTC
  return Number.isNaN(ms) ? undefined : ms / 1000;
}

export default function EvidenceTable({ fileId, protocols, selectedId, onSelect, refreshKey }: Props) {
  const [priorities, setPriorities] = useState<Priority[]>([]);
  const [protocol, setProtocol] = useState("");
  const [ip, setIp] = useState("");
  const [debouncedIp, setDebouncedIp] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [sortBy, setSortBy] = useState("priority");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<FindingPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => { setDebouncedIp(ip); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [ip]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getFindings(fileId, {
      page, pageSize: PAGE_SIZE, priorities, protocol, ip: debouncedIp,
      from: toEpoch(from), to: toEpoch(to), sortBy, sortDir,
    })
      .then((d) => { if (!cancelled) { setData(d); setError(null); } })
      .catch((e: unknown) => { if (!cancelled) setError(errorMessage(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [fileId, page, priorities, protocol, debouncedIp, from, to, sortBy, sortDir, refreshKey]);

  function toggle(p: Priority): void {
    setPriorities((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));
    setPage(1);
  }

  function sort(key: string): void {
    if (key === sortBy) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortBy(key); setSortDir("asc"); }
    setPage(1);
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Prioritized Evidence</h2>
        <div className="flex gap-1">
          {ALL.map((p) => (
            <button key={p} onClick={() => toggle(p)}
              className={`rounded px-2 py-1 text-xs font-semibold ${priorities.includes(p) ? PRIORITY_STYLES[p].badge : "border border-slate-700 text-slate-400"}`}>
              {p}
            </button>
          ))}
        </div>
        <select value={protocol} onChange={(e) => { setProtocol(e.target.value); setPage(1); }}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm">
          <option value="">All protocols</option>
          {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="Filter by IP"
          className="w-40 rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
        <label className="flex items-center gap-1 text-xs text-slate-400">
          From (UTC)
          <input type="datetime-local" value={from} onChange={(e) => { setFrom(e.target.value); setPage(1); }}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs" />
        </label>
        <label className="flex items-center gap-1 text-xs text-slate-400">
          To (UTC)
          <input type="datetime-local" value={to} onChange={(e) => { setTo(e.target.value); setPage(1); }}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs" />
        </label>
        <span className="text-xs text-slate-400">{data ? `${data.total.toLocaleString()} findings` : ""}{loading ? " · loading…" : ""}</span>
      </div>

      {error && <p className="rounded bg-red-950 px-3 py-2 text-sm text-red-300">{error}</p>}

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              {COLUMNS.map((c) => (
                <th key={c.key} onClick={() => sort(c.key)} className="cursor-pointer select-none whitespace-nowrap px-3 py-2 font-medium hover:text-slate-100">
                  {c.label}{sortBy === c.key ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {data?.items.map((f) => (
              <tr key={f.finding_id} onClick={() => onSelect(f.finding_id)}
                className={`cursor-pointer hover:bg-slate-900 ${selectedId === f.finding_id ? "bg-slate-800" : ""}`}>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono">{f.ts_first_utc.replace("T", " ").replace("Z", "")}</td>
                <td className="px-3 py-1.5 font-mono">{f.src_ip ?? "–"}</td>
                <td className="px-3 py-1.5 font-mono">{f.dst_ip ?? "–"}</td>
                <td className="px-3 py-1.5">{f.protocol}</td>
                <td className="px-3 py-1.5"><PriorityBadge priority={f.priority} overridden={f.overridden} /></td>
                <td className="max-w-md truncate px-3 py-1.5 text-slate-300" title={f.reason}>
                  <span className="mr-2 font-mono text-slate-500">{f.rule_id}</span>{f.reason}
                </td>
                <td className="px-3 py-1.5">{f.confidence.toFixed(2)}</td>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-sky-300">
                  {f.packet_refs.slice(0, 4).join(", ")}{f.packet_ref_count > 4 ? ` … (${f.packet_ref_count})` : ""}
                </td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-slate-500">No findings match.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-end gap-3 text-sm">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40">Prev</button>
        <span className="text-slate-400">Page {page} / {totalPages}</span>
        <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40">Next</button>
      </div>
    </section>
  );
}