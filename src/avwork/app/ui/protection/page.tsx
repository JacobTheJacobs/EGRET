import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type ProtectionStatus = {
  status: string;
  generated_at: string;
  av: {
    file_events?: number;
    malware_verdicts?: number;
    active_quarantine?: number;
    remediation_actions?: number;
    real_time_modes?: string[];
  };
};

export default function ProtectionPage() {
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/protection/status")
      .then((response) => {
        if (!response.ok) throw new Error(`protection:${response.status}`);
        return response.json();
      })
      .then(setStatus)
      .catch((err) => setError(String(err)));
  }, []);

  const av = status?.av ?? {};
  const counters: Array<{ label: string; value: number }> = [
    { label: "Files", value: av.file_events ?? 0 },
    { label: "Threat verdicts", value: av.malware_verdicts ?? 0 },
    { label: "Quarantine", value: av.active_quarantine ?? 0 },
    { label: "Remediation", value: av.remediation_actions ?? 0 },
  ];

  return (
    <AppShell active="protection">
      <section className="space-y-5">
        <div>
          <h2 className="text-2xl font-semibold">Protection</h2>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-3 md:grid-cols-4">
          {counters.map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
              <div className="text-sm text-slate-400">{label}</div>
              <div className="mt-2 text-3xl font-semibold text-slate-100">{value}</div>
            </div>
          ))}
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm font-medium text-slate-200">Protection modes</div>
          <div className="mt-3 flex flex-wrap gap-2">
            {(av.real_time_modes ?? []).map((mode) => (
              <span key={mode} className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">{mode}</span>
            ))}
          </div>
        </div>
      </section>
    </AppShell>
  );
}
