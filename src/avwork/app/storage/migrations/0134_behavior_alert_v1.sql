CREATE TABLE IF NOT EXISTS behavior_alert (
    behavior_alert_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_identity_id TEXT NULL,
    chain_id TEXT NULL,
    alert_kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    indicators_json TEXT NOT NULL DEFAULT '{}',
    recommendation TEXT NOT NULL,
    created_ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_behavior_alert_asset_created ON behavior_alert(asset_id, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_behavior_alert_severity ON behavior_alert(severity, created_ts DESC);
