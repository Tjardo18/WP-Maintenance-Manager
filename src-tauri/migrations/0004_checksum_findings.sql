PRAGMA foreign_keys = ON;

ALTER TABLE findings ADD COLUMN checksum_status TEXT;
ALTER TABLE findings ADD COLUMN observed_at TEXT;
ALTER TABLE findings ADD COLUMN site_id TEXT REFERENCES sites(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN scan_run_id TEXT REFERENCES scan_runs(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_findings_site_status ON findings(site_id, checksum_status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_status ON findings(scan_run_id, checksum_status);
