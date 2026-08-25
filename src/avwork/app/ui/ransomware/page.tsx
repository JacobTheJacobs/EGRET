import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type RansomwareSignal = {
  ransomware_signal_id: string;
  signal_kind: string;
  severity: string;
  protected_path?: string | null;
  action_recommendation: string;
  indicators_json?: Record<string, unknown>;
  created_ts: string;
};

export default function RansomwarePage() {
  const [items, setItems] = useState<RansomwareSignal[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/ransomware/signals")
      .then((response) => {
        if (!response.ok) throw new Error(`ransomware:${response.status}`);
        return response.json();
      })
      .then((payload) => setItems(payload.items ?? []))
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="ransomware">
      <section className="space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold">Ransomware Signals</h2>
          </div>
          <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">{items.length} signals</span>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-4">
          {items.map((item) => (
            <article key={item.ransomware_signal_id} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-lg font-medium text-slate-100">{item.signal_kind.replaceAll("_", " ")}</div>
                  <div className="mt-1 text-xs text-slate-500">{item.protected_path ?? "No protected path"} · {new Date(item.created_ts).toLocaleString()}</div>
                </div>
                <span className="rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs uppercase text-red-200">{item.severity}</span>
              </div>
              <p className="mt-4 text-sm text-slate-300">{item.action_recommendation}</p>
              <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {Object.entries(item.indicators_json ?? {}).map(([key, value]) => (
                  <div key={key} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div className="text-xs uppercase tracking-wide text-slate-500">{key}</div>
                    <div className="mt-1 text-sm text-slate-200">{String(value)}</div>
                  </div>
                ))}
              </div>
            </article>
          ))}
          {!items.length && !error && <div className="rounded-2xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No ransomware signals recorded.</div>}
        </div>
      </section>
    </AppShell>
  );
}
