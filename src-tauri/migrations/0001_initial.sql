PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    ssh_host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_username TEXT NOT NULL,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('key_file', 'password')),
    key_path TEXT,
    wordpress_path TEXT NOT NULL,
    credential_ref TEXT,
    pinned_host_key TEXT,
    status TEXT NOT NULL DEFAULT 'unscanned',
    wordpress_version TEXT,
    php_version TEXT,
    update_count INTEGER NOT NULL DEFAULT 0,
    security_status TEXT,
    last_scan_at TEXT,
    last_maintenance_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_checks (
    id TEXT PRIMARY KEY NOT NULL,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    check_key TEXT NOT NULL,
    label TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY NOT NULL,
    scan_check_id TEXT NOT NULL REFERENCES scan_checks(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    path TEXT
);

CREATE TABLE IF NOT EXISTS available_updates (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    current_version TEXT NOT NULL,
    new_version TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    UNIQUE(site_id, kind, slug)
);

CREATE TABLE IF NOT EXISTS maintenance_runs (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    duration_ms INTEGER,
    before_versions TEXT,
    after_versions TEXT
);

CREATE TABLE IF NOT EXISTS maintenance_steps (
    id TEXT PRIMARY KEY NOT NULL,
    maintenance_run_id TEXT NOT NULL REFERENCES maintenance_runs(id) ON DELETE CASCADE,
    step_key TEXT NOT NULL,
    label TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT,
    position INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_records (
    id TEXT PRIMARY KEY NOT NULL,
    maintenance_run_id TEXT NOT NULL REFERENCES maintenance_runs(id) ON DELETE CASCADE,
    local_path TEXT NOT NULL,
    size_bytes INTEGER,
    sha256 TEXT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_site_started ON scan_runs(site_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_maintenance_runs_site_started ON maintenance_runs(site_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_available_updates_site ON available_updates(site_id);
