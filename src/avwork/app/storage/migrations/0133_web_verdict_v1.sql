CREATE TABLE IF NOT EXISTS web_verdict (
    web_verdict_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    process_identity_id TEXT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    category TEXT NOT NULL,
    verdict TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence_score REAL NOT NULL DEFAULT 0,
    created_ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web_verdict_asset_created ON web_verdict(asset_id, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_web_verdict_verdict ON web_verdict(verdict, created_ts DESC);
