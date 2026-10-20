import type { Priority } from "../types";

export const PRIORITY_STYLES: Record<Priority, { badge: string; hex: string; label: string }> = {
  P1: { badge: "bg-red-600 text-white", hex: "#dc2626", label: "Critical" },
  P2: { badge: "bg-orange-500 text-white", hex: "#f97316", label: "High" },
  P3: { badge: "bg-yellow-500 text-black", hex: "#eab308", label: "Medium" },
  P4: { badge: "bg-slate-600 text-white", hex: "#64748b", label: "Routine" },
};

export default function PriorityBadge({ priority, overridden = false }: { priority: Priority; overridden?: boolean }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${PRIORITY_STYLES[priority].badge}`}
      title={overridden ? "Priority overridden by analyst" : PRIORITY_STYLES[priority].label}
    >
      {priority}{overridden ? "*" : ""}
    </span>
  );
}