import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type QuarantineRecord = {
  quarantine_record_id: string;
  original_path: string;
  quarantine_path: string;
  reason: string;
  restored: boolean;
  deleted: boolean;
  created_ts: string;
};

export default function QuarantinePage() {
  const [items, setItems] = useState<QuarantineRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/quarantine")
      .then((response) => {
        if (!response.ok) throw new Error(`quarantine:${response.status}`);
        return response.json();
      })
      .then((payload) => setItems(payload.items ?? []))
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="quarantine">
      <section className="space-y-5">
        <div>
          <h2 className="text-2xl font-semibold">Quarantine</h2>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-3">
          {items.map((item) => (
            <div key={item.quarantine_record_id} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-medium text-slate-100">{item.original_path}</div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-500">{item.quarantine_path}</div>
                </div>
                <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
                  {item.deleted ? "deleted" : item.restored ? "restored" : "contained"}
                </span>
              </div>
              <div className="mt-3 text-sm text-slate-400">{item.reason}</div>
            </div>
          ))}
          {!items.length && !error && <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No quarantined files.</div>}
        </div>
      </section>
    </AppShell>
  );
}
