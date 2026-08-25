import React from "react";
import type { TimelineItem } from "./api";

export function InvestigationTimeline({ items }: { items: TimelineItem[] }) {
  return (
    <div className="space-y-4">
      {items.map((item, index) => (
        <div key={`${item.kind}-${item.ts}-${index}`} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-sky-300">{item.kind.replace("_", " ")}</p>
              <h3 className="mt-1 text-lg font-medium text-slate-100">{item.title}</h3>
            </div>
            <time className="text-sm text-slate-400">{new Date(item.ts).toLocaleString()}</time>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {Object.entries(item.summary).map(([key, value]) => (
              <div key={key} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">{key}</div>
                <div className="mt-1 truncate text-sm text-slate-200">{value === null || value === undefined ? "none" : String(value)}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
      {!items.length && <div className="rounded-2xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No live investigation timeline events for this asset.</div>}
    </div>
  );
}
