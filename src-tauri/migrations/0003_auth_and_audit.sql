PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS auth_config (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    password_hash TEXT NOT NULL,
    idle_timeout_minutes INTEGER NOT NULL DEFAULT 15 CHECK (idle_timeout_minutes IN (5, 10, 15, 30, 60)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT REFERENCES sites(id) ON DELETE SET NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_site_created ON audit_events(site_id, created_at DESC);
