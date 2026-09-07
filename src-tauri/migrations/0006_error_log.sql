PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS error_logs (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'error', 'critical')),
    category TEXT NOT NULL,
    site_id TEXT REFERENCES sites(id) ON DELETE SET NULL,
    site_name TEXT,
    action TEXT NOT NULL,
    summary TEXT NOT NULL,
    technical_details TEXT,
    exit_code INTEGER,
    cause_chain TEXT,
    duration_ms INTEGER,
    retryable INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_error_logs_created ON error_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_logs_site_created ON error_logs(site_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_error_logs_category_created ON error_logs(category, created_at DESC);
