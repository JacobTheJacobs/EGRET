import React, { useEffect, useState } from "react";
import { AppShell } from "../app_shell";
import { fetchConnections } from "../connections/api";
import { fetchAssetTimeline, type TimelineItem } from "./api";
import { InvestigationTimeline } from "./timeline";

export default function InvestigationsPage() {
  const [assetId, setAssetId] = useState("");
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [availableAssets, setAvailableAssets] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void fetchConnections({ page_size: 100 })
      .then((rows) => {
        const assets = Array.from(new Set(rows.map((row) => row.asset_id).filter(Boolean)));
        setAvailableAssets(assets);
        setAssetId((current) => current || assets[0] || "");
      })
      .catch((err) => setError(String(err)));
  }, []);

  useEffect(() => {
    if (!assetId) {
      setItems([]);
      return;
    }
    void fetchAssetTimeline(assetId)
      .then((timeline) => {
        setItems(timeline);
        setError(null);
      })
      .catch((err) => {
        setItems([]);
        setError(String(err));
      });
  }, [assetId]);

  return (
    <AppShell active="investigations">
      <section className="space-y-6">
        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm uppercase tracking-[0.24em] text-sky-300">Investigations</p>
              <h2 className="text-2xl font-semibold tracking-tight">Asset timeline</h2>
              <p className="mt-2 text-sm text-slate-400">Live connection, decision, and trust-context events for one asset.</p>
            </div>
            <div className="grid gap-2">
              <input
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                className="rounded-2xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-slate-100"
                placeholder="asset id"
                list="known-assets"
              />
              <datalist id="known-assets">
                {availableAssets.map((asset) => <option key={asset} value={asset} />)}
              </datalist>
              <div className="text-xs text-slate-500">{availableAssets.length ? `${availableAssets.length} live assets discovered` : "No live assets discovered yet"}</div>
            </div>
          </div>
        </div>
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <InvestigationTimeline items={items} />
      </section>
    </AppShell>
  );
}
