CREATE TABLE IF NOT EXISTS policy_rule (
    rule_id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL,
    source TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask', 'observe_only')),
    ttl_seconds INTEGER NULL CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
    created_ts TIMESTAMP NOT NULL,
    updated_ts TIMESTAMP NOT NULL,
    created_by TEXT NULL,
    conditions_json JSONB NOT NULL,
    explanation_template TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_rule_enabled_priority ON policy_rule(enabled, priority DESC);
