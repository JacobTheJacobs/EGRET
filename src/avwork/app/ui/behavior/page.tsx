import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type BehaviorAlert = {
  behavior_alert_id: string;
  alert_kind: string;
  severity: string;
  recommendation: string;
  created_ts: string;
  indicators_json?: Record<string, unknown>;
};

type ThreatPayload = {
  behavior_alerts?: BehaviorAlert[];
};

export default function BehaviorPage() {
  const [items, setItems] = useState<BehaviorAlert[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/threats")
      .then((response) => {
        if (!response.ok) throw new Error(`behavior:${response.status}`);
        return response.json() as Promise<ThreatPayload>;
      })
      .then((payload) => setItems(payload.behavior_alerts ?? []))
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="behavior">
      <section className="space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold">Behavior Alerts</h2>
          </div>
          <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">{items.length} alerts</span>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-4">
          {items.map((item) => (
            <article key={item.behavior_alert_id} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-lg font-medium text-slate-100">{item.alert_kind.replaceAll("_", " ")}</div>
                  <div className="mt-1 text-xs text-slate-500">{new Date(item.created_ts).toLocaleString()}</div>
                </div>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs uppercase text-amber-200">{item.severity}</span>
              </div>
              <p className="mt-4 text-sm text-slate-300">{item.recommendation}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {Object.entries(item.indicators_json ?? {}).map(([key, value]) => (
                  <span key={key} className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
                    {key}: {String(value)}
                  </span>
                ))}
              </div>
            </article>
          ))}
          {!items.length && !error && <div className="rounded-2xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No behavior alerts recorded.</div>}
        </div>
      </section>
    </AppShell>
  );
}
