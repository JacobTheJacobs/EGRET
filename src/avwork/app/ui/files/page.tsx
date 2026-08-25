import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type FileEvent = {
  file_event_id: string;
  path: string;
  sha256: string;
  file_size: number;
  event_kind: string;
  origin_kind?: string | null;
  ts: string;
};

export default function FilesPage() {
  const [items, setItems] = useState<FileEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/files")
      .then((response) => {
        if (!response.ok) throw new Error(`files:${response.status}`);
        return response.json();
      })
      .then((payload) => setItems(payload.items ?? []))
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="files">
      <section className="space-y-5">
        <div className="flex items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold">Files</h2>
          </div>
          <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">{items.length} events</span>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Path</th>
                <th className="px-4 py-3 font-medium">Kind</th>
                <th className="px-4 py-3 font-medium">Origin</th>
                <th className="px-4 py-3 font-medium">Size</th>
                <th className="px-4 py-3 font-medium">SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950/60">
              {items.map((item) => (
                <tr key={item.file_event_id}>
                  <td className="max-w-md truncate px-4 py-3 text-slate-100">{item.path}</td>
                  <td className="px-4 py-3 text-slate-300">{item.event_kind}</td>
                  <td className="px-4 py-3 text-slate-300">{item.origin_kind ?? "local"}</td>
                  <td className="px-4 py-3 text-slate-300">{item.file_size.toLocaleString()}</td>
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-slate-500">{item.sha256}</td>
                </tr>
              ))}
              {!items.length && !error && (
                <tr>
                  <td className="px-4 py-8 text-center text-slate-500" colSpan={5}>No file events recorded.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}
