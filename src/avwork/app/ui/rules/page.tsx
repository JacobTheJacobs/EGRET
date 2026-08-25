import React, { useEffect, useMemo, useState } from "react";
import { AppShell } from "../app_shell";
import { createRule, fetchRules, updateRule, type RuleCreatePayload, type RuleRow } from "./api";
import { RuleEditor } from "./rule_editor";
import { RuleTable } from "./rule_table";

export type PolicyRuleRow = RuleRow;

export default function RulesPage() {
  const [rules, setRules] = useState<PolicyRuleRow[]>([]);
  const [draftName, setDraftName] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void fetchRules()
      .then((items) => {
        setRules(items);
        setError(null);
      })
      .catch((err) => {
        setRules([]);
        setError(String(err));
      })
      .finally(() => setLoading(false));
  }, []);

  const activeCount = useMemo(() => rules.filter((rule) => rule.enabled).length, [rules]);

  const handleCreate = async (rule: RuleCreatePayload) => {
    setSaving(true);
    setError(null);
    try {
      const created = await createRule(rule);
      setRules((current) => [created, ...current.filter((item) => item.rule_id !== created.rule_id)]);
      setDraftName("");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (ruleId: string) => {
    const current = rules.find((rule) => rule.rule_id === ruleId);
    if (!current) return;
    setError(null);
    try {
      const updated = await updateRule(ruleId, { enabled: !current.enabled });
      setRules((items) => items.map((rule) => (rule.rule_id === ruleId ? updated : rule)));
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <AppShell active="rules">
      <div className="space-y-6">
        <header className="flex flex-col gap-4 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-2xl">
          <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
            <div>
              <p className="text-sm uppercase tracking-[0.24em] text-sky-300">Rules</p>
              <h2 className="text-3xl font-semibold tracking-tight">Policy memory for outbound behavior</h2>
              <p className="mt-2 max-w-3xl text-sm text-slate-400">Review active policy, inspect temporary rules, and create process-aware allow or deny logic.</p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-sm text-slate-300">
              <div>{loading ? "Loading" : activeCount} active rules</div>
              <div>{rules.length - activeCount} disabled rules</div>
            </div>
          </div>
        </header>
        {error && <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        <div className="grid gap-6 lg:grid-cols-[1.1fr,0.9fr]">
          <RuleTable rules={rules} onToggle={handleToggle} loading={loading} />
          <RuleEditor draftName={draftName} onDraftNameChange={setDraftName} onCreate={handleCreate} saving={saving} />
        </div>
      </div>
    </AppShell>
  );
}
