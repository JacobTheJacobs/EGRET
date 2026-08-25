CREATE TABLE IF NOT EXISTS file_event (
    file_event_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_identity_id TEXT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    file_type TEXT NULL,
    origin_kind TEXT NULL,
    origin_source TEXT NULL,
    signer_name TEXT NULL,
    signer_status TEXT NULL,
    event_kind TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_event_asset_ts ON file_event(asset_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_file_event_sha256 ON file_event(sha256);
