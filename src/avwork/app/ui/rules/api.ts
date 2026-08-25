export type RuleCondition = {
  process_name?: string | null;
  process_path?: string | null;
  signer_name?: string | null;
  signer_status?: string | null;
  domain?: string | null;
  domain_suffix?: string | null;
  domain_suffix_not_in?: string[];
  remote_ip?: string | null;
  remote_port?: number | null;
  protocol?: string | null;
  network_zone?: string | null;
};

export type RuleRow = {
  rule_id: string;
  rule_name: string;
  enabled: boolean;
  priority: number;
  source: string;
  action: "allow" | "deny" | "ask" | "observe_only";
  ttl_seconds?: number | null;
  conditions: RuleCondition;
};

export type RuleCreatePayload = Omit<RuleRow, "rule_id"> & {
  created_by?: string | null;
  explanation_template?: string | null;
  apply_immediately?: boolean;
  enforcement_backend?: string | null;
  enforce_execute?: boolean;
};

export type RuleUpdatePayload = Partial<Pick<RuleRow, "rule_name" | "enabled" | "priority" | "ttl_seconds" | "conditions">> & {
  explanation_template?: string | null;
  apply_immediately?: boolean;
  enforcement_backend?: string | null;
  enforce_execute?: boolean;
};

export async function fetchRules(): Promise<RuleRow[]> {
  const response = await fetch(`/api/v1/rules`);
  if (!response.ok) throw new Error(`Failed to fetch rules: ${response.status}`);
  const payload = await response.json();
  return payload.items ?? [];
}

export async function createRule(payload: RuleCreatePayload): Promise<RuleRow> {
  const response = await fetch(`/api/v1/rules`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Failed to create rule: ${response.status}`);
  return response.json();
}

export async function updateRule(ruleId: string, payload: RuleUpdatePayload): Promise<RuleRow> {
  const response = await fetch(`/api/v1/rules/${encodeURIComponent(ruleId)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Failed to update rule: ${response.status}`);
  return response.json();
}
