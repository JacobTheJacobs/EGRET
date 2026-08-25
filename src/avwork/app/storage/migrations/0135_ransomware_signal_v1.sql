CREATE TABLE IF NOT EXISTS ransomware_signal (
    ransomware_signal_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_identity_id TEXT NULL,
    signal_kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    protected_path TEXT NULL,
    indicators_json TEXT NOT NULL DEFAULT '{}',
    action_recommendation TEXT NOT NULL,
    created_ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ransomware_signal_asset_created ON ransomware_signal(asset_id, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_ransomware_signal_severity ON ransomware_signal(severity, created_ts DESC);
