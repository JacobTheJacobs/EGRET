import React, { useEffect, useState } from "react";

import { AppShell } from "../app_shell";

type ReleaseManifest = {
  name: string;
  version: string;
  included_docs: string[];
  included_workflows: string[];
  included_installers: string[];
  included_runtime: string[];
  included_root_files: string[];
  notes: string[];
};

type ReadinessItem = {
  backend: string;
  runnable: boolean;
  ready_for_native_validation: boolean;
  command_preview: string[];
};

type RolloutReadiness = {
  status: string;
  ready_backends: number;
  total_backends: number;
  items: ReadinessItem[];
};

export default function ReleasePage() {
  const [manifest, setManifest] = useState<ReleaseManifest | null>(null);
  const [readiness, setReadiness] = useState<RolloutReadiness | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      fetch("/api/v1/release/manifest").then((response) => {
        if (!response.ok) throw new Error(`manifest:${response.status}`);
        return response.json();
      }),
      fetch("/api/v1/release/rollout-readiness").then((response) => {
        if (!response.ok) throw new Error(`readiness:${response.status}`);
        return response.json();
      }),
    ])
      .then(([manifestPayload, readinessPayload]) => {
        setManifest(manifestPayload);
        setReadiness(readinessPayload);
      })
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <AppShell active="release">
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-semibold">Release Readiness</h2>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-3 md:grid-cols-4">
          <Metric label="Docs" value={manifest?.included_docs.length ?? 0} />
          <Metric label="Workflows" value={manifest?.included_workflows.length ?? 0} />
          <Metric label="Installers" value={manifest?.included_installers.length ?? 0} />
          <Metric label="Runtime files" value={manifest?.included_runtime.length ?? 0} />
        </div>
        <section className="rounded-lg border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm text-slate-400">Candidate</div>
              <div className="mt-1 text-xl font-semibold text-slate-100">{manifest?.name ?? "egret"} {manifest?.version ?? ""}</div>
            </div>
            <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">
              {readiness?.status ?? "loading"}
            </span>
          </div>
          <div className="mt-4 text-sm text-slate-400">
            Native-ready backends: {readiness?.ready_backends ?? 0}/{readiness?.total_backends ?? 0}
          </div>
        </section>
        <section className="grid gap-3">
          {(readiness?.items ?? []).map((item) => (
            <div key={item.backend} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="font-medium capitalize text-slate-100">{item.backend}</div>
                <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
                  {item.ready_for_native_validation ? "ready" : item.runnable ? "runnable" : "needs host validation"}
                </span>
              </div>
              {(item.command_preview ?? []).length > 0 && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
                    {(item.command_preview ?? []).length} command
                    {(item.command_preview ?? []).length === 1 ? "" : "s"}
                  </summary>
                  <pre className="mt-2 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-400">
                    {(item.command_preview ?? []).join("\n")}
                  </pre>
                </details>
              )}
            </div>
          ))}
        </section>
      </div>
    </AppShell>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="mt-2 text-3xl font-semibold text-slate-100">{value}</div>
    </div>
  );
}
