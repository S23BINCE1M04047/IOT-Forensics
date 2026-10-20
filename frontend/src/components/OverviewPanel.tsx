import { CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Priority, Summary } from "../types";
import { PRIORITY_STYLES } from "./PriorityBadge";

const PALETTE = ["#38bdf8", "#a78bfa", "#34d399", "#f472b6", "#fbbf24", "#fb923c", "#94a3b8", "#2dd4bf"];
const TOOLTIP_STYLE = { background: "#0f172a", border: "1px solid #334155", fontSize: 12 };

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value.toLocaleString()}</div>
    </div>
  );
}

export default function OverviewPanel({ summary }: { summary: Summary }) {
  const prios: Priority[] = ["P1", "P2", "P3", "P4"];
  const perMinute = summary.packets_per_minute.map((m) => ({
    label: m.minute.slice(11, 16), packets: m.packets,
  }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Kpi label="Total packets" value={summary.total_packets} />
        <Kpi label="Connections" value={summary.total_connections} />
        <Kpi label="Unique src IPs" value={summary.unique_src_ips} />
        <Kpi label="Unique dst IPs" value={summary.unique_dst_ips} />
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {prios.map((p) => (
          <div key={p} className="rounded-lg border border-slate-800 bg-slate-900 p-4"
               style={{ borderLeft: `4px solid ${PRIORITY_STYLES[p].hex}` }}>
            <div className="text-xs uppercase tracking-wide text-slate-400">{p} · {PRIORITY_STYLES[p].label}</div>
            <div className="mt-1 text-2xl font-semibold">{summary.priority_counts[p].toLocaleString()}</div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-400">
        {summary.findings_total} findings · ruleset {summary.analysis_run?.ruleset_version ?? "?"} · baseline:{" "}
        {summary.analysis_run?.baseline_name ?? "none (baseline-dependent rules were skipped)"}.
        Priority is investigation priority, not proof of attack.
      </p>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h3 className="mb-2 text-sm font-semibold">Protocol distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={summary.protocols} dataKey="packets" nameKey="protocol" innerRadius={55} outerRadius={90}
                     paddingAngle={2} label={(e: { name?: string }) => e.name ?? ""}>
                  {summary.protocols.map((p, i) => <Cell key={p.protocol} fill={PALETTE[i % PALETTE.length]} />)}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h3 className="mb-2 text-sm font-semibold">Packets per minute (UTC)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={perMinute}>
                <CartesianGrid stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Line type="monotone" dataKey="packets" stroke="#38bdf8" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h3 className="mb-2 text-sm font-semibold">Top talkers (by bytes)</h3>
        <table className="w-full text-left text-xs">
          <thead className="text-slate-400">
            <tr><th className="py-1">Source</th><th>Destination</th><th className="text-right">Packets</th><th className="text-right">Bytes</th></tr>
          </thead>
          <tbody className="font-mono">
            {summary.top_talkers.map((t) => (
              <tr key={`${t.src_ip}>${t.dst_ip}`} className="border-t border-slate-800">
                <td className="py-1">{t.src_ip}</td><td>{t.dst_ip}</td>
                <td className="text-right">{t.packets.toLocaleString()}</td>
                <td className="text-right">{t.bytes.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}