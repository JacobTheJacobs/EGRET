CREATE TABLE IF NOT EXISTS process_identity (
    process_identity_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    parent_process_id INTEGER NULL,
    process_name TEXT NOT NULL,
    process_path TEXT NOT NULL,
    executable_hash TEXT NULL,
    signer_name TEXT NULL,
    signer_status TEXT NULL,
    package_id TEXT NULL,
    service_name TEXT NULL,
    first_seen_ts TEXT NULL,
    last_seen_ts TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_process_identity_asset_session_pid
    ON process_identity(asset_id, session_id, process_id);
