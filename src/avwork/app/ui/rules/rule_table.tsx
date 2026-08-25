import React from "react";
import type { PolicyRuleRow } from "./page";

type RuleTableProps = {
  rules: PolicyRuleRow[];
  onToggle: (ruleId: string) => void | Promise<void>;
  loading?: boolean;
};

export function RuleTable({ rules, onToggle, loading = false }: RuleTableProps) {
  return (
    <section className="overflow-hidden rounded-3xl border border-slate-800 bg-slate-900/80 shadow-2xl">
      <div className="border-b border-slate-800 px-5 py-4">
        <h2 className="text-xl font-semibold">Active policy set</h2>
        <p className="mt-1 text-sm text-slate-400">Rules are evaluated by priority and specificity before the app decides whether to allow, deny, or ask.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-950/80 text-slate-400">
            <tr>
              <th className="px-5 py-3 font-medium">Rule</th>
              <th className="px-5 py-3 font-medium">Action</th>
              <th className="px-5 py-3 font-medium">Conditions</th>
              <th className="px-5 py-3 font-medium">Priority</th>
              <th className="px-5 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.rule_id} className="border-t border-slate-800/70">
                <td className="px-5 py-4 align-top">
                  <div className="font-medium text-slate-100">{rule.rule_name}</div>
                  <div className="mt-1 text-xs text-slate-500">{rule.source} · {rule.rule_id}</div>
                </td>
                <td className="px-5 py-4 align-top">
                  <span className="rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-wide text-slate-200">{rule.action}</span>
                </td>
                <td className="px-5 py-4 align-top text-slate-300">
                  <div>Process: {rule.conditions.process_name ?? "Any"}</div>
                  <div>Domain suffix: {rule.conditions.domain_suffix ?? "Any"}</div>
                  <div>Zone: {rule.conditions.network_zone ?? "Any"}</div>
                </td>
                <td className="px-5 py-4 align-top text-slate-300">{rule.priority}</td>
                <td className="px-5 py-4 align-top">
                  <button onClick={() => onToggle(rule.rule_id)} className={`rounded-full px-3 py-1 text-xs font-medium ${rule.enabled ? "bg-emerald-400/20 text-emerald-300" : "bg-slate-700 text-slate-300"}`}>
                    {rule.enabled ? "Enabled" : "Disabled"}
                  </button>
                </td>
              </tr>
            ))}
            {!rules.length && (
              <tr className="border-t border-slate-800/70">
                <td className="px-5 py-8 text-center text-slate-500" colSpan={5}>
                  {loading ? "Loading live policy rules..." : "No live policy rules recorded."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
