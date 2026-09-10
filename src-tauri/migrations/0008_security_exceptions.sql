PRAGMA foreign_keys = ON;

ALTER TABLE findings ADD COLUMN disposition TEXT NOT NULL DEFAULT 'active';
ALTER TABLE findings ADD COLUMN exception_id TEXT;
ALTER TABLE findings ADD COLUMN trusted_file_id TEXT;
ALTER TABLE findings ADD COLUMN policy_reason TEXT;

CREATE TABLE IF NOT EXISTS finding_exceptions (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    check_type TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'site' CHECK (scope = 'site'),
    reason TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS trusted_files (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    trusted_sha256 TEXT NOT NULL,
    current_sha256 TEXT,
    size_bytes INTEGER NOT NULL,
    current_size_bytes INTEGER,
    modified_at_snapshot TEXT,
    current_modified_at TEXT,
    file_type TEXT NOT NULL DEFAULT 'regular',
    status TEXT NOT NULL DEFAULT 'trusted' CHECK (status IN ('trusted','changed','missing','unchecked')),
    trusted_at TEXT NOT NULL,
    last_checked_at TEXT,
    note TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_finding_exceptions_match
    ON finding_exceptions(site_id,check_type,finding_type,target,active,expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_exceptions_active_unique
    ON finding_exceptions(site_id,check_type,finding_type,target) WHERE active=1;
CREATE INDEX IF NOT EXISTS idx_trusted_files_site_path
    ON trusted_files(site_id,relative_path,active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_files_active_unique
    ON trusted_files(site_id,relative_path) WHERE active=1;
