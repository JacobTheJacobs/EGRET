import React, { useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "../app_shell";
import { captureHostConnections, fetchConnections } from "./api";
import { ConnectionDetailsDrawer } from "./connection_details_drawer";
import { ConnectionFilters } from "./connection_filters";
import { ConnectionTable } from "./connection_table";
import type { ConnectionRow } from "./types";

export default function ConnectionsPage() {
  const [rows, setRows] = useState<ConnectionRow[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("all");
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [captureStatus, setCaptureStatus] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  const autoCaptureAttempted = useRef(false);

  async function refreshConnections(): Promise<ConnectionRow[]> {
    const items = await fetchConnections({ page_size: 100 });
    setRows(items);
    setLastUpdated(new Date().toLocaleTimeString());
    setError(null);
    return items;
  }

  async function runHostCapture(auto = false) {
    setCapturing(true);
    setCaptureStatus(auto ? "No persisted rows found. Capturing current host sockets..." : "Capturing current host sockets...");
    try {
      const summary = await captureHostConnections(100);
      setCaptureStatus(
        summary.status === "ok"
          ? `Captured ${summary.captured} live host connection${summary.captured === 1 ? "" : "s"} from ${summary.source}.`
          : `Host capture unavailable from ${summary.source}: ${summary.message ?? "no collector output"}`,
      );
      await refreshConnections();
    } catch (err) {
      setCaptureStatus(null);
      setError(String(err));
    } finally {
      setCapturing(false);
    }
  }

  useEffect(() => {
    let active = true;
    const refresh = () => {
      void fetchConnections({ page_size: 100 })
        .then((items) => {
          if (!active) return;
          setRows(items);
          setLastUpdated(new Date().toLocaleTimeString());
          setError(null);
          if (!items.length && !autoCaptureAttempted.current) {
            autoCaptureAttempted.current = true;
            void runHostCapture(true);
          }
        })
        .catch((err) => {
          if (!active) return;
          setRows([]);
          setError(String(err));
        });
    };
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const destination = `${row.destination.matched_domain || ""} ${row.destination.sni || ""} ${row.destination.ip}`.toLowerCase();
      const process = `${row.process.name} ${row.process.signer_name || ""}`.toLowerCase();
      const matchesSearch = !search || destination.includes(search.toLowerCase()) || process.includes(search.toLowerCase());
      const matchesVerdict = verdict === "all" || row.verdict === verdict;
      return matchesSearch && matchesVerdict;
    });
  }, [rows, search, verdict]);

  return (
    <AppShell active="connections">
      <div className="space-y-6">
        <div>
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-3xl font-semibold text-slate-100">Connections</h2>
            </div>
            <div className="rounded-full border border-slate-800 px-3 py-1 text-xs text-slate-400">
              {lastUpdated ? `refreshed ${lastUpdated}` : "connecting"}
            </div>
          </div>
        </div>
        {error && <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        {captureStatus && <div className="rounded-2xl border border-sky-500/30 bg-sky-500/10 p-4 text-sm text-sky-100">{captureStatus}</div>}
        <ConnectionFilters search={search} verdict={verdict} onSearchChange={setSearch} onVerdictChange={setVerdict} />
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
          <div>
            <div className="font-medium text-slate-100">Live source</div>
            <div className="mt-1 text-slate-400">Connections are populated from authenticated ingest or this host's current established sockets.</div>
          </div>
          <button
            type="button"
            disabled={capturing}
            onClick={() => void runHostCapture(false)}
            className="rounded-xl bg-sky-400 px-4 py-2 font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {capturing ? "Capturing..." : "Capture host connections now"}
          </button>
        </div>
        <ConnectionTable rows={filteredRows} onSelect={(row) => setSelectedConnectionId(row.connection_id)} />
        {!filteredRows.length && (
          <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/70 p-6 text-sm text-slate-400">
            <div className="font-medium text-slate-200">No live connection rows matched the current view.</div>
            <div className="mt-2">
              Use authenticated sensor ingest for continuous telemetry, or capture current host sockets now. If capture returns zero rows, there may be no established non-loopback sockets at this moment or the OS collector is unavailable.
            </div>
          </div>
        )}
        <ConnectionDetailsDrawer connectionId={selectedConnectionId} onClose={() => setSelectedConnectionId(null)} />
      </div>
    </AppShell>
  );
}
