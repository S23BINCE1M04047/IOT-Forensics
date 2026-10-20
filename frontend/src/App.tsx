import { useCallback, useEffect, useState } from "react";
import { createBaseline, errorMessage, getStatus, getSummary, listBaselines, startAnalysis } from "./api/client";
import EvidenceDrawer from "./components/EvidenceDrawer";
import EvidenceTable from "./components/EvidenceTable";
import NavBar from "./components/NavBar";
import type { View } from "./components/NavBar";
import OverviewPanel from "./components/OverviewPanel";
import PacketTable from "./components/PacketTable";
import UploadZone from "./components/UploadZone";
import type { Baseline, Capture, StatusInfo, Summary } from "./types";

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [capture, setCapture] = useState<Capture | null>(null);
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [baselines, setBaselines] = useState<Baseline[]>([]);
  const [baselineId, setBaselineId] = useState<number | null>(null);
  const [baselineName, setBaselineName] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [version, setVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const refreshBaselines = useCallback(async (): Promise<void> => {
    try {
      setBaselines(await listBaselines());
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => { void refreshBaselines(); }, [refreshBaselines]);

  async function runAnalysis(c: Capture): Promise<void> {
    setError(null);
    setSelectedId(null);
    try {
      setStatus(await startAnalysis(c.file_id, baselineId));
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function handleUploaded(c: Capture): Promise<void> {
    setSummary(null);
    setCapture(c);
    await runAnalysis(c);
  }

  async function saveBaseline(): Promise<void> {
    if (!capture || !baselineName.trim()) return;
    try {
      const b = await createBaseline(baselineName.trim(), capture.file_id);
      setBaselineName("");
      await refreshBaselines();
      setBaselineId(b.id);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  const state = status?.status;

  useEffect(() => {
    if (!capture || (state !== "queued" && state !== "running")) return;
    const timer = setInterval(() => {
      getStatus(capture.file_id).then(setStatus).catch((e: unknown) => setError(errorMessage(e)));
    }, 1000);
    return () => clearInterval(timer);
  }, [capture, state]);

  useEffect(() => {
    if (capture && state === "done") {
      getSummary(capture.file_id)
        .then((s) => { setSummary(s); setVersion((v) => v + 1); })
        .catch((e: unknown) => setError(errorMessage(e)));
    }
  }, [capture, state]);

  const busy = state === "queued" || state === "running";
  const protocols = summary ? summary.protocols.map((p) => p.protocol) : [];

  return (
    <div className="flex min-h-screen">
      <NavBar view={view} onChange={setView} disabled={!summary} />

      <main className="min-w-0 flex-1 space-y-6 p-6">
        <UploadZone onUploaded={(c) => void handleUploaded(c)} disabled={busy} />

        <section className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm">
          <label className="flex items-center gap-2">
            Baseline for analysis
            <select value={baselineId ?? ""} onChange={(e) => setBaselineId(e.target.value ? Number(e.target.value) : null)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1">
              <option value="">None (baseline rules skipped)</option>
              {baselines.map((b) => <option key={b.id} value={b.id}>{b.name} ({b.packet_count} pkts)</option>)}
            </select>
          </label>
          {capture && state === "done" && (
            <>
              <button onClick={() => void runAnalysis(capture)} className="rounded border border-slate-700 px-3 py-1 hover:bg-slate-800">Re-run analysis</button>
              <input value={baselineName} onChange={(e) => setBaselineName(e.target.value)} placeholder="Name to save this capture as a baseline"
                className="w-72 rounded border border-slate-700 bg-slate-950 px-2 py-1" />
              <button disabled={!baselineName.trim()} onClick={() => void saveBaseline()}
                className="rounded border border-slate-700 px-3 py-1 hover:bg-slate-800 disabled:opacity-40">Save as baseline</button>
            </>
          )}
        </section>

        {error && <p className="rounded bg-red-950 px-3 py-2 text-sm text-red-300">{error}</p>}

        {capture && (
          <section className="space-y-2 rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm">
            <div className="font-medium">{capture.original_filename}</div>
            <div className="break-all font-mono text-xs text-slate-300">SHA-256: {capture.sha256}</div>
            <div className="text-xs text-slate-400">
              {(capture.size_bytes / 1024).toFixed(1)} KB · uploaded {capture.uploaded_at} · tool {capture.tool_version}
            </div>
            {status && (
              <div className="text-xs">
                Status: <span className="font-semibold">{status.status}</span>
                {busy && ` · ${status.packets_parsed.toLocaleString()} packets parsed so far`}
                {status.status === "error" && <span className="text-red-400"> · {status.error_message}</span>}
              </div>
            )}
            {status?.integrity_warning && <p className="rounded bg-red-900 px-3 py-2 font-semibold text-red-100">{status.integrity_warning}</p>}
            {status?.status === "done" && status.integrity_ok && (
              <p className="text-xs text-emerald-400">Integrity verified: SHA-256 after analysis matches the upload hash.</p>
            )}
          </section>
        )}

        {summary && capture && !busy && (
          <>
            {view === "overview" && <OverviewPanel summary={summary} />}
            {view === "evidence" && (
              <EvidenceTable fileId={capture.file_id} protocols={protocols} selectedId={selectedId}
                onSelect={setSelectedId} refreshKey={version} />
            )}
            {view === "packets" && <PacketTable fileId={capture.file_id} protocols={protocols} />}
          </>
        )}
      </main>

      {selectedId !== null && (
        <EvidenceDrawer key={selectedId} findingId={selectedId} onClose={() => setSelectedId(null)}
          onChanged={() => { setVersion((v) => v + 1); void (capture && getSummary(capture.file_id).then(setSummary)); }} />
      )}
    </div>
  );
}