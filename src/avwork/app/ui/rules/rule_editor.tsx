import React, { useState } from "react";
import type { PolicyRuleRow } from "./page";
import type { RuleCreatePayload } from "./api";

type RuleEditorProps = {
  draftName: string;
  onDraftNameChange: (value: string) => void;
  onCreate: (rule: RuleCreatePayload) => void | Promise<void>;
  saving?: boolean;
};

export function RuleEditor({ draftName, onDraftNameChange, onCreate, saving = false }: RuleEditorProps) {
  const [action, setAction] = useState<PolicyRuleRow["action"]>("allow");
  const [processName, setProcessName] = useState("Firefox");
  const [domainSuffix, setDomainSuffix] = useState("mozilla.org");
  const [networkZone, setNetworkZone] = useState("public_internet");
  const [priority, setPriority] = useState(100);
  const [ttlHours, setTtlHours] = useState(0);

  return (
    <section className="rounded-3xl border border-slate-800 bg-slate-900/80 p-5 shadow-2xl">
      <div className="mb-5">
        <h2 className="text-xl font-semibold">Create rule</h2>
        <p className="mt-1 text-sm text-slate-400">Build simple process and domain scoped policy without leaving the main app shell.</p>
      </div>

      <div className="grid gap-4">
        <label className="grid gap-2 text-sm text-slate-300">
          Rule name
          <input className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={draftName} onChange={(event) => onDraftNameChange(event.target.value)} placeholder="Allow Firefox to mozilla.org" />
        </label>

        <div className="grid gap-4 md:grid-cols-2">
          <label className="grid gap-2 text-sm text-slate-300">
            Action
            <select className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={action} onChange={(event) => setAction(event.target.value as PolicyRuleRow["action"])}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
              <option value="ask">Ask</option>
              <option value="observe_only">Observe only</option>
            </select>
          </label>
          <label className="grid gap-2 text-sm text-slate-300">
            Priority
            <input type="number" className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={priority} onChange={(event) => setPriority(Number(event.target.value))} />
          </label>
        </div>

        <label className="grid gap-2 text-sm text-slate-300">
          Process name
          <input className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={processName} onChange={(event) => setProcessName(event.target.value)} />
        </label>

        <div className="grid gap-4 md:grid-cols-2">
          <label className="grid gap-2 text-sm text-slate-300">
            Domain suffix
            <input className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={domainSuffix} onChange={(event) => setDomainSuffix(event.target.value)} />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">
            Network zone
            <select className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={networkZone} onChange={(event) => setNetworkZone(event.target.value)}>
              <option value="public_internet">Public internet</option>
              <option value="private_lan">Private LAN</option>
              <option value="vpn">VPN</option>
              <option value="loopback">Loopback</option>
            </select>
          </label>
        </div>

        <label className="grid gap-2 text-sm text-slate-300">
          Temporary rule duration (hours)
          <input type="number" min={0} className="rounded-2xl border border-slate-700 bg-slate-950 px-3 py-2" value={ttlHours} onChange={(event) => setTtlHours(Number(event.target.value))} />
        </label>

        <button
          className="rounded-2xl bg-sky-400 px-4 py-3 text-sm font-semibold text-slate-950 shadow-lg hover:bg-sky-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-300"
          disabled={saving}
          onClick={() =>
            onCreate({
              rule_name: draftName || `${action} ${processName} ${domainSuffix}`,
              enabled: true,
              priority,
              source: "user",
              action,
              ttl_seconds: ttlHours > 0 ? ttlHours * 3600 : null,
              conditions: {
                process_name: processName,
                domain_suffix: domainSuffix,
                network_zone: networkZone,
              },
              created_by: "ui",
              apply_immediately: false,
              enforce_execute: false,
            })
          }
        >
          {saving ? "Saving rule..." : "Save rule"}
        </button>
      </div>
    </section>
  );
}
