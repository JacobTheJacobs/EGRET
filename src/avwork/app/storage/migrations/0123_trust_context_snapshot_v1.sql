CREATE TABLE IF NOT EXISTS trust_context_snapshot (
    trust_context_snapshot_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    snapshot_ts TIMESTAMP NOT NULL,
    risky_ble_signature_counter BOOLEAN NOT NULL DEFAULT FALSE,
    rogue_ble_counter_reuse BOOLEAN NOT NULL DEFAULT FALSE,
    trust_score DOUBLE PRECISION NULL,
    drift_score DOUBLE PRECISION NULL,
    supporting_context_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_trust_context_snapshot_asset_session_ts
    ON trust_context_snapshot (asset_id, session_id, snapshot_ts DESC);
