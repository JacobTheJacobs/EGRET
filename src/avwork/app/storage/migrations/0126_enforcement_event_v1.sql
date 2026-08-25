CREATE TABLE IF NOT EXISTS enforcement_event (
    enforcement_event_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    backend TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    connection_id TEXT NULL,
    policy_decision_id TEXT NULL,
    message TEXT NULL,
    command_preview TEXT NOT NULL DEFAULT '[]',
    applied_ts TEXT NOT NULL,
    effective_until TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_enforcement_event_rule_applied ON enforcement_event(rule_id, applied_ts DESC);
CREATE INDEX IF NOT EXISTS idx_enforcement_event_connection ON enforcement_event(connection_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_event_decision ON enforcement_event(policy_decision_id);
