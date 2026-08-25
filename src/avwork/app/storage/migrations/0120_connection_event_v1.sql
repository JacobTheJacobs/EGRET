CREATE TABLE IF NOT EXISTS connection_event (
    connection_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    asset_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    process_identity_id TEXT NOT NULL,
    destination_identity_id TEXT NULL,
    start_ts TIMESTAMP NOT NULL,
    end_ts TIMESTAMP NULL,
    direction TEXT NOT NULL CHECK (direction IN ('outbound', 'inbound')),
    protocol TEXT NULL,
    transport TEXT NOT NULL,
    local_ip TEXT NULL,
    local_port INTEGER NULL CHECK (local_port BETWEEN 1 AND 65535),
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL CHECK (remote_port BETWEEN 1 AND 65535),
    interface_name TEXT NULL,
    network_zone TEXT NOT NULL,
    vpn_state TEXT NULL,
    bytes_out BIGINT NULL DEFAULT 0,
    bytes_in BIGINT NULL DEFAULT 0,
    duration_ms BIGINT NULL,
    trust_context_snapshot_id TEXT NULL,
    matched_rule_id TEXT NULL,
    policy_decision_id TEXT NULL,
    first_seen_on_asset BOOLEAN NULL,
    first_seen_in_fleet BOOLEAN NULL,
    prevalence_on_asset DOUBLE PRECISION NULL,
    prevalence_in_fleet DOUBLE PRECISION NULL,
    flow_risk_score DOUBLE PRECISION NULL,
    rule_suggestion_score DOUBLE PRECISION NULL,
    anomaly_score DOUBLE PRECISION NULL
);

CREATE INDEX IF NOT EXISTS idx_connection_event_asset_ts ON connection_event(asset_id, start_ts DESC);
CREATE INDEX IF NOT EXISTS idx_connection_event_process ON connection_event(process_identity_id, start_ts DESC);
CREATE INDEX IF NOT EXISTS idx_connection_event_remote ON connection_event(remote_ip, remote_port);
