CREATE TABLE IF NOT EXISTS training_feedback_event (
    training_feedback_event_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    label TEXT NOT NULL,
    label_source TEXT NOT NULL,
    features_hash TEXT NOT NULL,
    generated_ts TIMESTAMP NOT NULL,
    superseded_by TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_training_feedback_event_connection_id
    ON training_feedback_event (connection_id, generated_ts DESC);
