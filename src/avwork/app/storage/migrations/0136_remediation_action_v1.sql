CREATE TABLE IF NOT EXISTS remediation_action (
    remediation_action_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_identity_id TEXT NULL,
    related_object_id TEXT NULL,
    action_kind TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    backend_result TEXT NULL,
    initiated_by TEXT NOT NULL,
    created_ts TEXT NOT NULL,
    completed_ts TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_action_asset_created ON remediation_action(asset_id, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_action_status ON remediation_action(status, created_ts DESC);
