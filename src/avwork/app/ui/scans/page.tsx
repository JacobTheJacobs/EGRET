import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";

type FileEvent = {
  file_event_id: string;
  path: string;
  sha256: string;
  file_size: number;
  event_kind: string;
  origin_kind?: string | null;
  ts: string;
};

type ScanResult = {
  file_event: FileEvent;
  verdict: {
    malware_verdict_id: string;
    verdict: string;
    verdict_source: string;
    signature_name?: string | null;
    family_name?: string | null;
    confidence_score: number;
  };
  quarantine_record?: {
    quarantine_record_id: string;
    reason: string;
    quarantine_path: string;
  } | null;
};

const DEFAULT_CONTENT = "Paste bytes or text to scan here.";

function encodeBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`${url}:${response.status}`);
  return response.json();
}

export default function ScansPage() {
  const [modes, setModes] = useState<string[]>([]);
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [assetId, setAssetId] = useState("local-host");
  const [sessionId, setSessionId] = useState("operator-session");
  const [path, setPath] = useState("/tmp/operator-scan.txt");
  const [eventKind, setEventKind] = useState("demand_scan");
  const [originKind, setOriginKind] = useState("manual");
  const [signerStatus, setSignerStatus] = useState("unknown");
  const [content, setContent] = useState(DEFAULT_CONTENT);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshEvents = () => {
    fetchJson<{ items: FileEvent[] }>("/api/v1/files?page_size=8")
      .then((payload) => setEvents(payload.items ?? []))
      .catch((err) => setError(String(err)));
  };

  useEffect(() => {
    fetchJson<{ items: string[] }>("/api/v1/scans/modes")
      .then((payload) => setModes(payload.items ?? []))
      .catch((err) => setError(String(err)));
    refreshEvents();
  }, []);

  const submitScan = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const payload = {
        asset_id: assetId,
        session_id: sessionId,
        path,
        content_base64: encodeBase64(content),
        origin_kind: originKind || null,
        signer_status: signerStatus || null,
        event_kind: eventKind,
        quarantine_on_malicious: true,
      };
      const scan = await fetchJson<ScanResult>("/api/v1/files/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setResult(scan);
      refreshEvents();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AppShell active="scans">
      <section className="space-y-6">
        <div>
          <h2 className="text-2xl font-semibold">Scans</h2>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
          <form onSubmit={submitScan} className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-lg font-medium text-slate-100">Live operator scan</h3>
                <p className="mt-1 text-sm text-slate-400">Submits to <span className="font-mono text-slate-300">POST /api/v1/files/scan</span> and writes to the same stores used by Files, Threats, Quarantine, and Protection.</p>
              </div>
              <button
                type="submit"
                disabled={submitting || !content || !path || !assetId || !sessionId}
                className="rounded-xl bg-sky-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {submitting ? "Scanning..." : "Run scan"}
              </button>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Asset">
                <input value={assetId} onChange={(event) => setAssetId(event.target.value)} className="scan-input" />
              </Field>
              <Field label="Session">
                <input value={sessionId} onChange={(event) => setSessionId(event.target.value)} className="scan-input" />
              </Field>
              <Field label="Path">
                <input value={path} onChange={(event) => setPath(event.target.value)} className="scan-input" />
              </Field>
              <Field label="Mode">
                <select value={eventKind} onChange={(event) => setEventKind(event.target.value)} className="scan-input">
                  {(modes.length ? modes : ["demand_scan"]).map((mode) => (
                    <option key={mode} value={mode}>{mode}</option>
                  ))}
                </select>
              </Field>
              <Field label="Origin">
                <input value={originKind} onChange={(event) => setOriginKind(event.target.value)} className="scan-input" />
              </Field>
              <Field label="Signer status">
                <select value={signerStatus} onChange={(event) => setSignerStatus(event.target.value)} className="scan-input">
                  <option value="unknown">unknown</option>
                  <option value="unsigned">unsigned</option>
                  <option value="trusted">trusted</option>
                </select>
              </Field>
            </div>
            <Field label="Content">
              <textarea
                value={content}
                onChange={(event) => setContent(event.target.value)}
                rows={8}
                className="scan-input font-mono"
              />
            </Field>
          </form>
          <div className="space-y-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-lg font-medium text-slate-100">Latest result</h3>
              {!result ? (
                <div className="mt-4 rounded-xl border border-dashed border-slate-800 p-5 text-sm text-slate-500">No scan has been submitted from this page yet.</div>
              ) : (
                <div className="mt-4 space-y-3">
                  <div className={`rounded-xl border p-4 ${result.verdict.verdict === "malicious" ? "border-red-500/30 bg-red-500/10" : result.verdict.verdict === "suspicious" ? "border-amber-500/30 bg-amber-500/10" : "border-emerald-500/20 bg-emerald-500/5"}`}>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Verdict</div>
                    <div className="mt-1 text-2xl font-semibold text-slate-100">{result.verdict.verdict}</div>
                    <div className="mt-2 text-sm text-slate-300">
                      {result.verdict.verdict_source} | confidence {Math.round(result.verdict.confidence_score * 100)}%
                    </div>
                  </div>
                  <ResultRow label="File event" value={result.file_event.file_event_id} />
                  <ResultRow label="SHA-256" value={result.file_event.sha256} />
                  <ResultRow label="Signature" value={result.verdict.signature_name ?? result.verdict.family_name ?? "none"} />
                  <ResultRow label="Quarantine" value={result.quarantine_record ? `${result.quarantine_record.reason} (${result.quarantine_record.quarantine_record_id})` : "none"} />
                </div>
              )}
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-lg font-medium text-slate-100">Registered scan modes</h3>
              <div className="mt-3 flex flex-wrap gap-2">
                {modes.map((mode) => (
                  <span key={mode} className="rounded-full border border-slate-700 px-3 py-1 font-mono text-xs text-sky-300">{mode}</span>
                ))}
                {!modes.length && <span className="text-sm text-slate-500">No scan modes reported.</span>}
              </div>
            </div>
          </div>
        </div>
        <div className="overflow-hidden rounded-2xl border border-slate-800">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Recent persisted file events</th>
                <th className="px-4 py-3 font-medium">Mode</th>
                <th className="px-4 py-3 font-medium">Size</th>
                <th className="px-4 py-3 font-medium">SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950/60">
              {events.map((item) => (
                <tr key={item.file_event_id}>
                  <td className="max-w-md truncate px-4 py-3 text-slate-100">{item.path}</td>
                  <td className="px-4 py-3 font-mono text-xs text-sky-300">{item.event_kind}</td>
                  <td className="px-4 py-3 text-slate-300">{item.file_size.toLocaleString()}</td>
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-slate-500">{item.sha256}</td>
                </tr>
              ))}
              {!events.length && (
                <tr>
                  <td className="px-4 py-8 text-center text-slate-500" colSpan={4}>No file events recorded.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="text-slate-400">{label}</span>
      {children}
    </label>
  );
}

function ResultRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 truncate font-mono text-sm text-slate-200">{value}</div>
    </div>
  );
}
