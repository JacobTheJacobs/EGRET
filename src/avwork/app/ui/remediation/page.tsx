import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type RemediationAction = {
  remediation_action_id: string;
  action_kind: string;
  target_type: string;
  status: string;
  backend_result?: string | null;
  initiated_by: string;
  created_ts: string;
  completed_ts?: string | null;
};

export default function RemediationPage() {
  const [items, setItems] = useState<RemediationAction[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/remediation")
      .then((response) => {
        if (!response.ok) throw new Error(`remediation:${response.status}`);
        return response.json();
      })
      .then((payload) => setItems(payload.items ?? []))
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="remediation">
      <section className="space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold">Remediation</h2>
          </div>
          <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">{items.length} actions</span>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Initiated By</th>
                <th className="px-4 py-3 font-medium">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950/60">
              {items.map((item) => (
                <tr key={item.remediation_action_id}>
                  <td className="px-4 py-3 text-slate-100">{item.action_kind.replaceAll("_", " ")}</td>
                  <td className="px-4 py-3 text-slate-300">{item.target_type}</td>
                  <td className="px-4 py-3">
                    <span className="rounded-full border border-slate-700 px-2 py-1 text-xs uppercase text-slate-300">{item.status}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-300">{item.initiated_by}</td>
                  <td className="max-w-md truncate px-4 py-3 text-slate-400">{item.backend_result ?? "No backend result yet."}</td>
                </tr>
              ))}
              {!items.length && !error && (
                <tr>
                  <td className="px-4 py-8 text-center text-slate-500" colSpan={5}>No remediation actions recorded.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}
