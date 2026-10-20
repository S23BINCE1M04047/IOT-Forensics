import { useRef, useState } from "react";
import type { DragEvent } from "react";
import { errorMessage, uploadPcap } from "../api/client";
import type { Capture } from "../types";

const MAX_MB = 200; // keep in sync with backend IFTD_MAX_UPLOAD_MB

interface Props {
  onUploaded: (capture: Capture) => void;
  disabled?: boolean;
}

export default function UploadZone({ onUploaded, disabled = false }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File): Promise<void> {
    setError(null);
    const lower = file.name.toLowerCase();
    if (!lower.endsWith(".pcap") && !lower.endsWith(".pcapng")) {
      setError("Only .pcap and .pcapng files are accepted.");
      return;
    }
    if (file.size > MAX_MB * 1024 * 1024) {
      setError(`File is larger than ${MAX_MB} MB.`);
      return;
    }
    setBusy(true);
    try {
      onUploaded(await uploadPcap(file, note.trim() || undefined));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function onDrop(e: DragEvent<HTMLDivElement>): void {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && !disabled && !busy) void handleFile(file);
  }

  const inactive = disabled || busy;

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !inactive && inputRef.current?.click()}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 text-center transition
          ${dragging ? "border-sky-400 bg-sky-950/40" : "border-slate-700 bg-slate-900"}
          ${inactive ? "cursor-not-allowed opacity-60" : "hover:border-sky-500"}`}
      >
        <p className="text-sm font-medium">
          {busy ? "Uploading and hashing…" : "Drag & drop a PCAP here, or click to choose"}
        </p>
        <p className="mt-1 text-xs text-slate-400">.pcap / .pcapng, max {MAX_MB} MB. Original is stored unchanged.</p>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void handleFile(f);
            e.target.value = "";
          }}
        />
      </div>
      <input
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Analyst note (optional, stored with chain-of-custody metadata)"
        className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm placeholder:text-slate-500"
      />
      {error && <p className="rounded bg-red-950 px-3 py-2 text-sm text-red-300">{error}</p>}
    </div>
  );
}