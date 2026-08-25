export type EnforcementEvent = {
  enforcement_event_id: string;
  rule_id: string;
  backend: "macos" | "windows" | "linux";
  action: "allow" | "deny";
  status: "pending" | "applied" | "failed" | "skipped" | "stale";
  message?: string | null;
  command_preview: string[];
  applied_ts: string;
};

export type ReconciliationIssue = {
  rule_id: string;
  status: string;
  summary: string;
  latest_enforcement_event_id?: string | null;
};

export async function fetchEnforcementEvents(baseUrl = ""): Promise<EnforcementEvent[]> {
  const res = await fetch(`${baseUrl}/api/v1/enforcement/events`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load enforcement events");
  const payload = await res.json();
  return payload.items ?? [];
}

export async function fetchEnforcementReconciliation(baseUrl = ""): Promise<ReconciliationIssue[]> {
  const res = await fetch(`${baseUrl}/api/v1/enforcement/reconciliation`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load enforcement reconciliation");
  const payload = await res.json();
  return payload.items ?? [];
}
