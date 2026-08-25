CREATE TABLE IF NOT EXISTS quarantine_record (
    quarantine_record_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    reason TEXT NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_ts TEXT NOT NULL,
    updated_ts TEXT NOT NULL,
    malware_verdict_id TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_record_asset_created ON quarantine_record(asset_id, created_ts DESC);
