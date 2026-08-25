ALTER TABLE enforcement_event ADD COLUMN backend_rule_ref TEXT NULL;
ALTER TABLE enforcement_event ADD COLUMN execution_mode TEXT NULL DEFAULT 'simulated';
ALTER TABLE enforcement_event ADD COLUMN backend_state TEXT NULL DEFAULT 'unknown';
