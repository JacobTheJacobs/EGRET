import React from "react";

type Props = {
  search: string;
  verdict: string;
  onSearchChange: (value: string) => void;
  onVerdictChange: (value: string) => void;
};

export function ConnectionFilters({ search, verdict, onSearchChange, onVerdictChange }: Props) {
  return (
    <div className="grid gap-3 rounded-2xl bg-white p-4 shadow-sm md:grid-cols-3">
      <input
        className="rounded-xl border px-3 py-2 text-sm"
        placeholder="Search app, domain, IP"
        value={search}
        onChange={(event) => onSearchChange(event.target.value)}
      />
      <select
        className="rounded-xl border px-3 py-2 text-sm"
        value={verdict}
        onChange={(event) => onVerdictChange(event.target.value)}
      >
        <option value="all">All verdicts</option>
        <option value="allow">Allow</option>
        <option value="deny">Deny</option>
        <option value="ask">Ask</option>
      </select>
      <div className="flex items-center rounded-xl border px-3 py-2 text-sm text-slate-500">
        Live outbound visibility with explainable verdicts
      </div>
    </div>
  );
}
