CREATE INDEX IF NOT EXISTS idx_connection_event_zone_ts
    ON connection_event(network_zone, start_ts DESC);

CREATE INDEX IF NOT EXISTS idx_process_identity_name
    ON process_identity(process_name);

CREATE INDEX IF NOT EXISTS idx_destination_identity_domain
    ON destination_identity(matched_domain, sni);

CREATE INDEX IF NOT EXISTS idx_policy_rule_created_ts
    ON policy_rule(created_ts DESC);

CREATE INDEX IF NOT EXISTS idx_policy_decision_expires_at
    ON policy_decision(expires_at);
