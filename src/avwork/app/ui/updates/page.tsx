import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type ContentStatus = {
  version: string;
  installed: boolean;
  path: string;
  signatures: number;
  malicious_hashes: number;
  malicious_domains: number;
  phishing_domains: number;
  updated_at?: string | null;
};

export default function UpdatesPage() {
  const [status, setStatus] = useState<ContentStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/updates/content/status")
      .then((response) => {
        if (!response.ok) throw new Error(`updates:${response.status}`);
        return response.json();
      })
      .then(setStatus)
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="updates">
      <section className="space-y-5">
        <div>
          <h2 className="text-2xl font-semibold">Content Updates</h2>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm text-slate-400">Active pack</div>
              <div className="mt-1 text-xl font-semibold text-slate-100">{status?.version ?? "unknown"}</div>
            </div>
            <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">
              {status?.installed ? "installed" : "builtin"}
            </span>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-4">
            <Metric label="Signatures" value={status?.signatures ?? 0} />
            <Metric label="Malicious hashes" value={status?.malicious_hashes ?? 0} />
            <Metric label="Malicious domains" value={status?.malicious_domains ?? 0} />
            <Metric label="Phishing domains" value={status?.phishing_domains ?? 0} />
          </div>
          <div className="mt-4 truncate font-mono text-xs text-slate-500">{status?.path ?? ""}</div>
        </div>
      </section>
    </AppShell>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
    </div>
  );
}
