import { useEffect, useState } from "react";
import { errorMessage, getPackets } from "../api/client";
import type { PacketPage, PacketRow } from "../types";

interface Props {
  fileId: string;
  protocols: string[];
}

const PAGE_SIZE = 100;

function info(p: PacketRow): string {
  if (p.dns_query) return `DNS ${p.dns_qtype ?? ""} ${p.dns_query}${p.dns_answers ? ` → ${p.dns_answers}` : ""}`;
  if (p.http_method) return `${p.http_method} ${p.http_host ?? ""}${p.http_uri ?? ""}`;
  return p.payload_preview ? p.payload_preview.replace(/\s+/g, " ").slice(0, 80) : "";
}

const endpoint = (ip: string | null, port: number | null): string =>
  ip === null ? "–" : port === null ? ip : `${ip}:${port}`;

export default function PacketTable({ fileId, protocols }: Props) {
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [protocol, setProtocol] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PacketPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => { setDebouncedQ(q); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getPackets(fileId, { page, pageSize: PAGE_SIZE, q: debouncedQ, protocol })
      .then((d) => { if (!cancelled) { setData(d); setError(null); } })
      .catch((e: unknown) => { if (!cancelled) setError(errorMessage(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [fileId, page, debouncedQ, protocol]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Packets</h2>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search IP, DNS name, host, protocol, or packet #"
          className="min-w-[18rem] flex-1 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
        />
        <select
          value={protocol}
          onChange={(e) => { setProtocol(e.target.value); setPage(1); }}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
        >
          <option value="">All protocols</option>
          {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <span className="text-xs text-slate-400">{data ? `${data.total.toLocaleString()} packets` : ""}{loading ? " · loading…" : ""}</span>
      </div>

      {error && <p className="rounded bg-red-950 px-3 py-2 text-sm text-red-300">{error}</p>}

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              {["#", "Time (UTC)", "Source", "Destination", "Proto", "Len", "Flags", "Info"].map((h) => (
                <th key={h} className="px-3 py-2 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 font-mono">
            {data?.items.map((p) => (
              <tr key={p.packet_number} className="hover:bg-slate-900">
                <td className="px-3 py-1.5 text-sky-300">{p.packet_number}</td>
                <td className="whitespace-nowrap px-3 py-1.5">{p.ts_utc.replace("T", " ").replace("Z", "")}</td>
                <td className="px-3 py-1.5">{endpoint(p.src_ip, p.src_port)}</td>
                <td className="px-3 py-1.5">{endpoint(p.dst_ip, p.dst_port)}</td>
                <td className="px-3 py-1.5">{p.protocol}</td>
                <td className="px-3 py-1.5">{p.length}</td>
                <td className="px-3 py-1.5">{p.flags ?? ""}</td>
                <td className="max-w-md truncate px-3 py-1.5 text-slate-300" title={info(p)}>{info(p)}</td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-slate-500">No packets match.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-end gap-3 text-sm">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}
          className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40">Prev</button>
        <span className="text-slate-400">Page {page} / {totalPages}</span>
        <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}
          className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40">Next</button>
      </div>
    </section>
  );
}