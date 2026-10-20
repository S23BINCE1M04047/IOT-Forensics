export type View = "overview" | "evidence" | "packets";

const ITEMS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Prioritized Evidence" },
  { id: "packets", label: "Raw Packets" },
];

interface Props {
  view: View;
  onChange: (v: View) => void;
  disabled: boolean;
}

export default function NavBar({ view, onChange, disabled }: Props) {
  return (
    <nav className="w-52 shrink-0 border-r border-slate-800 p-3">
      <div className="mb-4 text-sm font-semibold">IoT Forensic Triage</div>
      <ul className="space-y-1">
        {ITEMS.map((i) => (
          <li key={i.id}>
            <button
              disabled={disabled}
              onClick={() => onChange(i.id)}
              className={`w-full rounded px-3 py-2 text-left text-sm disabled:opacity-40 ${
                view === i.id ? "bg-sky-900 text-sky-100" : "hover:bg-slate-900"
              }`}
            >
              {i.label}
            </button>
          </li>
        ))}
      </ul>
      <p className="mt-6 text-xs text-slate-500">Timeline and Report arrive in Phases 3 and 4.</p>
    </nav>
  );
}