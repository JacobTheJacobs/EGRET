import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";
import { fetchEnforcementEvents, fetchEnforcementReconciliation, type EnforcementEvent, type ReconciliationIssue } from "./api";

export default function EnforcementPage() {
  const [events, setEvents] = useState<EnforcementEvent[]>([]);
  const [issues, setIssues] = useState<ReconciliationIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([fetchEnforcementEvents(), fetchEnforcementReconciliation()])
      .then(([nextEvents, nextIssues]) => {
        setEvents(nextEvents);
        setIssues(nextIssues);
        setError(null);
      })
      .catch((err) => {
        setEvents([]);
        setIssues([]);
        setError(String(err));
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <AppShell active="enforcement">
      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-3xl border border-slate-800 bg-slate-900/60 p-6 shadow-2xl">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold">Enforcement audit</h2>
              <p className="text-sm text-slate-400">Live backend enforcement plans recorded from rule applications.</p>
            </div>
            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
              {loading ? "loading" : `${events.length} events`}
            </span>
          </div>
          {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
          <div className="space-y-4">
            {events.map((event) => (
              <div key={event.enforcement_event_id} className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-slate-700 px-2 py-1 text-xs uppercase text-slate-300">{event.backend}</span>
                  <span className={`rounded-full px-2 py-1 text-xs uppercase ${event.status === "applied" ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300"}`}>{event.status}</span>
                  <span className="text-sm text-slate-400">Rule {event.rule_id}</span>
                </div>
                {event.message && <p className="mt-2 text-sm text-slate-300">{event.message}</p>}
                {event.command_preview.length > 0 && (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
                      {event.command_preview.length} command{event.command_preview.length === 1 ? "" : "s"}
                    </summary>
                    <pre className="mt-2 overflow-x-auto rounded-2xl border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">{event.command_preview.join("\n")}</pre>
                  </details>
                )}
              </div>
            ))}
            {!events.length && !error && <div className="rounded-2xl border border-dashed border-slate-800 p-6 text-sm text-slate-400">{loading ? "Loading live enforcement events..." : "No enforcement events recorded yet."}</div>}
          </div>
        </section>
        <section className="rounded-3xl border border-slate-800 bg-slate-900/60 p-6 shadow-2xl">
          <h2 className="text-xl font-semibold">Reconciliation</h2>
          <div className="mt-4 space-y-3">
            {issues.map((issue) => (
              <div key={`${issue.rule_id}-${issue.status}`} className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4">
                <div className="text-sm font-medium text-amber-200">{issue.rule_id}</div>
                <div className="mt-1 text-xs uppercase tracking-wide text-amber-300">{issue.status}</div>
                <p className="mt-2 text-sm text-slate-300">{issue.summary}</p>
              </div>
            ))}
            {!issues.length && !error && <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-sm text-emerald-200">{loading ? "Loading reconciliation..." : "No reconciliation issues detected."}</div>}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
