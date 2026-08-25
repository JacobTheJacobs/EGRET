CREATE TABLE IF NOT EXISTS destination_identity (
    destination_identity_id TEXT PRIMARY KEY,
    canonical_name TEXT NULL,
    matched_domain TEXT NULL,
    sni TEXT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NULL,
    certificate_subject TEXT NULL,
    certificate_issuer TEXT NULL,
    certificate_fingerprint TEXT NULL,
    service_fingerprint TEXT NULL,
    resolver_source TEXT NULL,
    first_seen_ts TEXT NULL,
    last_seen_ts TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_destination_identity_ip_port
    ON destination_identity(ip, port);
