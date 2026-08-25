import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type MalwareVerdict = {
  malware_verdict_id: string;
  file_event_id: string;
  verdict: string;
  verdict_source: string;
  signature_name?: string | null;
  family_name?: string | null;
  confidence_score: number;
  created_ts: string;
};

type WebVerdict = {
  web_verdict_id: string;
  url: string;
  domain: string;
  category: string;
  verdict: string;
  source: string;
  confidence_score: number;
  created_ts: string;
};

type BehaviorAlert = {
  behavior_alert_id: string;
  alert_kind: string;
  severity: string;
  recommendation: string;
  created_ts: string;
};

type RansomwareSignal = {
  ransomware_signal_id: string;
  signal_kind: string;
  severity: string;
  protected_path?: string | null;
  action_recommendation: string;
  created_ts: string;
};

type ThreatPayload = {
  malware_verdicts: MalwareVerdict[];
  web_verdicts: WebVerdict[];
  behavior_alerts: BehaviorAlert[];
  ransomware_signals: RansomwareSignal[];
  total: number;
};

function confidence(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export default function ThreatsPage() {
  const [payload, setPayload] = useState<ThreatPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/threats")
      .then((response) => {
        if (!response.ok) throw new Error(`threats:${response.status}`);
        return response.json() as Promise<ThreatPayload>;
      })
      .then((nextPayload) => {
        setPayload(nextPayload);
        setError(null);
      })
      .catch((err) => setError(String(err)));
  }, []);

  const stats: Array<{ label: string; value: number }> = [
    { label: "Malware", value: payload?.malware_verdicts.length ?? 0 },
    { label: "Blocked web", value: payload?.web_verdicts.length ?? 0 },
    { label: "Behavior", value: payload?.behavior_alerts.length ?? 0 },
    { label: "Ransomware", value: payload?.ransomware_signals.length ?? 0 },
  ];

  return (
    <AppShell active="threats">
      <section className="space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold">Threats</h2>
          </div>
          <span className="rounded-full border border-slate-700 px-3 py-1 text-sm text-slate-300">{payload?.total ?? 0} total findings</span>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-3 md:grid-cols-4">
          {stats.map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
              <div className="text-sm text-slate-400">{label}</div>
              <div className="mt-2 text-3xl font-semibold text-slate-100">{value}</div>
            </div>
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <h3 className="text-lg font-semibold">Malware Verdicts</h3>
            <div className="mt-4 space-y-3">
              {(payload?.malware_verdicts ?? []).map((item) => (
                <div key={item.malware_verdict_id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium text-slate-100">{item.signature_name ?? item.family_name ?? item.verdict}</span>
                    <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs uppercase text-red-200">{item.verdict}</span>
                  </div>
                  <div className="mt-2 text-xs text-slate-500">File event {item.file_event_id} · {item.verdict_source} · {confidence(item.confidence_score)}</div>
                </div>
              ))}
              {!(payload?.malware_verdicts.length ?? 0) && <div className="text-sm text-slate-500">No live malware verdicts.</div>}
            </div>
          </section>
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <h3 className="text-lg font-semibold">Web Verdicts</h3>
            <div className="mt-4 space-y-3">
              {(payload?.web_verdicts ?? []).map((item) => (
                <div key={item.web_verdict_id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium text-slate-100">{item.domain}</span>
                    <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs uppercase text-amber-200">{item.verdict}</span>
                  </div>
                  <div className="mt-2 truncate text-xs text-slate-500">{item.url}</div>
                  <div className="mt-1 text-xs text-slate-500">{item.category} · {item.source} · {confidence(item.confidence_score)}</div>
                </div>
              ))}
              {!(payload?.web_verdicts.length ?? 0) && <div className="text-sm text-slate-500">No live blocked web verdicts.</div>}
            </div>
          </section>
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <h3 className="text-lg font-semibold">Behavior Alerts</h3>
            <div className="mt-4 space-y-3">
              {(payload?.behavior_alerts ?? []).map((item) => (
                <div key={item.behavior_alert_id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium text-slate-100">{item.alert_kind.replaceAll("_", " ")}</span>
                    <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs uppercase text-amber-200">{item.severity}</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-400">{item.recommendation}</p>
                </div>
              ))}
              {!(payload?.behavior_alerts.length ?? 0) && <div className="text-sm text-slate-500">No live behavior alerts.</div>}
            </div>
          </section>
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <h3 className="text-lg font-semibold">Ransomware Signals</h3>
            <div className="mt-4 space-y-3">
              {(payload?.ransomware_signals ?? []).map((item) => (
                <div key={item.ransomware_signal_id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium text-slate-100">{item.signal_kind.replaceAll("_", " ")}</span>
                    <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs uppercase text-red-200">{item.severity}</span>
                  </div>
                  <div className="mt-2 text-xs text-slate-500">{item.protected_path ?? "No protected path"}</div>
                  <p className="mt-2 text-sm text-slate-400">{item.action_recommendation}</p>
                </div>
              ))}
              {!(payload?.ransomware_signals.length ?? 0) && <div className="text-sm text-slate-500">No live ransomware signals.</div>}
            </div>
          </section>
        </div>
      </section>
    </AppShell>
  );
}
