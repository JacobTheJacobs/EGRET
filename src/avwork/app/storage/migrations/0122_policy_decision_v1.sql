CREATE TABLE IF NOT EXISTS policy_decision (
    policy_decision_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    matched_rule_id TEXT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'ask', 'defer')),
    decision_source TEXT NOT NULL CHECK (decision_source IN ('user_prompt', 'user_rule', 'admin_rule', 'system_default', 'recommendation')),
    prompt_shown BOOLEAN NOT NULL DEFAULT FALSE,
    prompt_response TEXT NULL,
    user_reason TEXT NULL,
    expires_at TIMESTAMP NULL,
    confidence_score DOUBLE PRECISION NULL,
    recommendation_kind TEXT NULL,
    created_ts TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_decision_connection ON policy_decision(connection_id, created_ts DESC);
