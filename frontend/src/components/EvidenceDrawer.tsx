import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { errorMessage, getFinding, patchFinding } from "../api/client";
import type { FindingDetail, Priority } from "../types";
import PriorityBadge from "./PriorityBadge";

interface Props {
  findingId: number;
  onClose: () => void;
  onChanged: () => void;
}

const CLEAR = "__clear__";

function endpoint(ip: string | null, port: number | null): string {
  return ip === null ? "–" : port === null ? ip : `${ip}:${port}`;
}

export default function EvidenceDrawer({ findingId, onClose, onChanged }: Props) {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [choice, setChoice] = useState<string>("P1");
  const [note, setNote] = useState("");
  const [analyst, setAnalyst] = useState("");
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    try {
      const d = await getFinding(findingId);
      setDetail(d);
      setChoice(d.priority);
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [findingId]);

  useEffect(() => { setDetail(null); setNote(""); void load(); }, [load]);

  async function submit(e: FormEvent): Promise<void> {
    e.preventDefault();
    setSaving(true);
    try {
      await patchFinding(findingId, {
        priority: choice === CLEAR ? null : (choice as Priority),
        analyst_note: note.trim(),
        analyst: analyst.trim(),
      });
      setNote("");
      await load();
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function copyFilter(): Promise<void> {
    if (!detail) return;
    await navigator.clipboard.writeText(detail.wireshark_filter);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <aside className="fixed right-0 top-0 z-10 h-full w-[32rem] max-w-full overflow-y-auto border-l border-slate-700 bg-slate-900 p-4 text-sm shadow-xl">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-base font-semibold">Finding #{findingId}</h2>
        <button onClick={onClose} className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800">Close</button>
      </div>
      {error && <p className="mb-3 rounded bg-red-950 px-3 py-2 text-red-300">{error}</p>}
      {!detail && !error && <p className="text-slate-400">Loading…</p>}

      {detail && (
        <div className="space-y-4">
          <section className="space-y-1">
            <div className="flex items-center gap-2">
              <PriorityBadge priority={detail.priority} overridden={detail.overridden} />
              {detail.overridden && <span className="text-xs text-slate-400">engine said {detail.original_priority}</span>}
              <span className="font-mono text-xs text-slate-400">{detail.rule_id}</span>
            </div>
            <p>{detail.reason}</p>
            <p className="font-mono text-xs text-slate-400">
              {detail.src_ip ?? "–"} → {detail.dst_ip ?? "–"} · {detail.protocol} · {detail.ts_first_utc}
            </p>
          </section>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase text-slate-400">Confidence {detail.confidence.toFixed(2)}</h3>
            {Object.entries(detail.confidence_breakdown).map(([k, v]) => (
              <div key={k} className="mb-1 flex items-center gap-2 text-xs">
                <span className="w-48 shrink-0 truncate text-slate-300">{k}</span>
                <div className="h-2 flex-1 rounded bg-slate-800"><div className="h-2 rounded bg-sky-500" style={{ width: `${Math.min(100, Math.max(0, v) * 100)}%` }} /></div>
                <span className="w-10 text-right font-mono">{v.toFixed(2)}</span>
              </div>
            ))}
          </section>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase text-slate-400">Rule evidence</h3>
            <dl className="space-y-0.5 font-mono text-xs">
              {Object.entries(detail.details).map(([k, v]) => (
                <div key={k} className="flex gap-2"><dt className="w-40 shrink-0 text-slate-400">{k}</dt><dd className="break-all">{typeof v === "string" ? v : JSON.stringify(v)}</dd></div>
              ))}
            </dl>
          </section>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase text-slate-400">Open in Wireshark: paste into the display filter</h3>
            <div className="flex gap-2">
              <code className="max-h-24 flex-1 overflow-auto break-all rounded bg-slate-950 p-2 text-xs">{detail.wireshark_filter}</code>
              <button onClick={() => void copyFilter()} className="self-start rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800">{copied ? "Copied" : "Copy"}</button>
            </div>
            <p className="mt-1 text-xs text-slate-500">Frame numbers match the original, unmodified PCAP.</p>
          </section>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase text-slate-400">
              Supporting packets ({detail.packets_shown} of {detail.packet_ref_count} shown)
            </h3>
            <div className="overflow-x-auto rounded border border-slate-800">
              <table className="w-full text-left font-mono text-[11px]">
                <thead className="bg-slate-950 text-slate-400"><tr><th className="px-2 py-1">#</th><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Len</th></tr></thead>
                <tbody>
                  {detail.packets.map((p) => (
                    <tr key={p.packet_number} className="border-t border-slate-800 align-top">
                      <td className="px-2 py-1 text-sky-300">{p.packet_number}</td>
                      <td className="whitespace-nowrap pr-2">{p.ts_utc.slice(11, 23)}</td>
                      <td className="pr-2">{endpoint(p.src_ip, p.src_port)}</td>
                      <td className="pr-2">{endpoint(p.dst_ip, p.dst_port)}</td>
                      <td className="pr-2">{p.protocol}</td>
                      <td>{p.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {detail.packets.some((p) => p.payload_preview) && (
              <div className="mt-2 space-y-1">
                <h4 className="text-xs text-slate-400">Payload previews (printable only)</h4>
                {detail.packets.filter((p) => p.payload_preview).slice(0, 5).map((p) => (
                  <pre key={p.packet_number} className="overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-[11px]">#{p.packet_number}: {p.payload_preview}</pre>
                ))}
              </div>
            )}
          </section>

          <form onSubmit={(e) => void submit(e)} className="space-y-2 rounded border border-slate-700 p-3">
            <h3 className="text-xs font-semibold uppercase text-slate-400">Analyst override</h3>
            {detail.analyst_note && (
              <p className="text-xs text-slate-400">Last note by {detail.overridden_by} ({detail.overridden_at}): {detail.analyst_note}</p>
            )}
            <div className="flex gap-2">
              <select value={choice} onChange={(e) => setChoice(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1">
                {(["P1", "P2", "P3", "P4"] as Priority[]).map((p) => <option key={p} value={p}>{p}</option>)}
                <option value={CLEAR}>Clear override (use engine priority)</option>
              </select>
              <input required value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="Your name"
                className="flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1" />
            </div>
            <textarea required minLength={3} value={note} onChange={(e) => setNote(e.target.value)} rows={3}
              placeholder="Why? (required, stored with the override)"
              className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1" />
            <button disabled={saving} className="rounded bg-sky-700 px-3 py-1 text-xs font-semibold hover:bg-sky-600 disabled:opacity-50">
              {saving ? "Saving…" : "Save override"}
            </button>
          </form>
        </div>
      )}
    </aside>
  );
}