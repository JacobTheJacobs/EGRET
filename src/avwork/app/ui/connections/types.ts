export type ConnectionFilters = {
  asset_id?: string;
  process_name?: string;
  domain?: string;
  ip?: string;
  port?: number;
  verdict?: string;
  network_zone?: string;
  page?: number;
  page_size?: number;
};

export type ConnectionRow = {
  connection_id: string;
  asset_id: string;
  session_id: string;
  start_ts: string;
  process: {
    name: string;
    path?: string;
    signer_name?: string;
    signer_status?: string;
  };
  destination: {
    matched_domain?: string;
    ip: string;
    port: number;
    protocol?: string;
    sni?: string;
    certificate_subject?: string;
    certificate_issuer?: string;
  };
  verdict: string;
  verdict_source?: string;
  network_zone: string;
  flow_risk_score?: number;
  rule_suggestion_score?: number;
  trust_flags?: {
    risky_ble_signature_counter?: boolean;
    rogue_ble_counter_reuse?: boolean;
  };
  explanation_preview?: string;
};

export type ConnectionDetail = {
  connection: Record<string, unknown>;
  process: Record<string, unknown>;
  destination: Record<string, unknown> | null;
  policy: {
    matched_rule_id?: string | null;
    matched_rule?: Record<string, unknown> | null;
    decision?: string | null;
    decision_source?: string | null;
    expires_at?: string | null;
  };
  trust_context: Record<string, unknown>;
  explanation: {
    headline: string;
    short_rationale: string;
    confidence_score: number;
    user_factors: string[];
    machine_factors: string[];
  };
  related_events: unknown[];
};

export type DecisionCreateRequest = {
  connection_id: string;
  action: "allow" | "block" | "ask" | "defer";
  ttl_seconds?: number;
  persist_as_rule?: boolean;
  user_reason?: string;
  process_name?: string;
  domain_suffix?: string;
  network_zone?: string;
};

export type DecisionCreateResponse = {
  policy_decision_id: string;
  rule_id?: string | null;
  decision: string;
  expires_at?: string | null;
};

export type HostCaptureSummary = {
  status: string;
  source: string;
  captured: number;
  skipped: number;
  connection_ids: string[];
  message?: string | null;
};
