import React, { useEffect, useState } from 'react';
import { AppShell } from '../app_shell';
import { fetchHealthStatus, type HealthStatus } from './api';

export default function HealthPage(): React.ReactElement {
  const [state, setState] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHealthStatus().then(setState).catch((err) => setError(String(err)));
  }, []);

  if (error) {
    return (
      <AppShell active="health">
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>
      </AppShell>
    );
  }

  return (
    <AppShell active="health">
      <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold">Health</h2>
      </div>
      {!state ? (
        <div className="rounded-lg border border-dashed border-slate-800 p-8 text-sm text-slate-500">Loading health...</div>
      ) : (
        <>
      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm text-slate-400">Status</div>
          <div className="mt-2 text-2xl font-semibold text-slate-100">{state.status}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm text-slate-400">Ingest auth</div>
          <div className={`mt-2 text-2xl font-semibold ${state.security.ingest_token_configured ? 'text-emerald-200' : 'text-amber-200'}`}>
            {state.security.ingest_token_configured ? 'ready' : 'missing'}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm text-slate-400">Connections</div>
          <div className="mt-2 text-2xl font-semibold text-slate-100">{state.counts.connections}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm text-slate-400">Rules</div>
          <div className="mt-2 text-2xl font-semibold text-slate-100">{state.counts.rules}</div>
        </div>
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="text-lg font-medium text-slate-100">Live ingest security</h3>
        <div className="mt-2 text-sm text-slate-400">
          Protected write endpoints require one of: {state.security.ingest_auth_headers.join(', ')}.
        </div>
        <div className="mt-2 text-sm text-slate-400">
          Secret values exposed by health: {String(state.security.secret_values_exposed)}.
        </div>
      </div>
      <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="text-lg font-medium text-slate-100">Backend capabilities</h3>
        {state.enforcement_capabilities.map((item) => (
          <div key={item.backend} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="font-medium capitalize text-slate-100">{item.backend}</div>
            <div className="mt-1 text-sm text-slate-400">Runnable: {String(item.runnable)} | Native enabled: {String(item.native_execution_enabled)}</div>
            <div className="text-sm text-slate-400">Available: {item.available_binaries.join(', ') || 'none'}</div>
            <div className="text-sm text-slate-400">Missing: {item.missing_binaries.join(', ') || 'none'}</div>
          </div>
        ))}
      </div>
        </>
      )}
      </div>
    </AppShell>
  );
}
