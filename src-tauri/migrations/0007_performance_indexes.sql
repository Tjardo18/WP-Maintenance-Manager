PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS idx_scan_checks_run_key ON scan_checks(scan_run_id, check_key);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(scan_check_id);
CREATE INDEX IF NOT EXISTS idx_maintenance_steps_run_position ON maintenance_steps(maintenance_run_id, position);
CREATE INDEX IF NOT EXISTS idx_available_updates_site_checked ON available_updates(site_id, checked_at DESC);
