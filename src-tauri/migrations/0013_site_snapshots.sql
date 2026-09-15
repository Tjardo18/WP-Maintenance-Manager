PRAGMA foreign_keys = ON;

CREATE TABLE site_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    scan_run_id TEXT REFERENCES scan_runs(id) ON DELETE SET NULL,
    maintenance_run_id TEXT REFERENCES maintenance_runs(id) ON DELETE SET NULL,
    source TEXT NOT NULL CHECK (source IN ('scan','baseline','pre_maintenance','post_maintenance','manual')),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    status TEXT NOT NULL CHECK (status IN ('complete','partial')),
    wordpress_root_identity TEXT,
    scan_timestamp TEXT NOT NULL,
    app_version TEXT,
    section_status_json TEXT NOT NULL,
    payload_encoding TEXT NOT NULL DEFAULT 'json_utf8' CHECK (payload_encoding IN ('json_utf8','gzip_json')),
    payload BLOB NOT NULL,
    is_baseline INTEGER NOT NULL DEFAULT 0 CHECK (is_baseline IN (0,1)),
    previous_snapshot_id TEXT REFERENCES site_snapshots(id) ON DELETE SET NULL
);

CREATE TABLE snapshot_diffs (
    id TEXT PRIMARY KEY NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    from_snapshot_id TEXT NOT NULL REFERENCES site_snapshots(id) ON DELETE CASCADE,
    to_snapshot_id TEXT NOT NULL REFERENCES site_snapshots(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    origin TEXT NOT NULL CHECK (origin IN ('scan','maintenance','manual','unknown')),
    maintenance_run_id TEXT REFERENCES maintenance_runs(id) ON DELETE SET NULL,
    change_count INTEGER NOT NULL DEFAULT 0 CHECK (change_count >= 0),
    UNIQUE(from_snapshot_id, to_snapshot_id)
);

CREATE TABLE snapshot_diff_sections (
    diff_id TEXT NOT NULL REFERENCES snapshot_diffs(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN ('core','plugins','themes','users','configuration','cron','files')),
    status TEXT NOT NULL CHECK (status IN ('compared','unavailable')),
    reason TEXT,
    PRIMARY KEY(diff_id, category)
);

CREATE TABLE snapshot_changes (
    id TEXT PRIMARY KEY NOT NULL,
    diff_id TEXT NOT NULL REFERENCES snapshot_diffs(id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    from_snapshot_id TEXT NOT NULL REFERENCES site_snapshots(id) ON DELETE CASCADE,
    to_snapshot_id TEXT NOT NULL REFERENCES site_snapshots(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN ('core','plugins','themes','users','configuration','cron','files')),
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('added','removed','updated','enabled','disabled','activated','deactivated','role_changed','version_changed','configuration_changed','scheduled','unscheduled','unknown')),
    field TEXT,
    old_value_json TEXT,
    new_value_json TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('info','attention','warning','critical')),
    summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    origin TEXT NOT NULL CHECK (origin IN ('scan','maintenance','manual','unknown')),
    seen INTEGER NOT NULL DEFAULT 0 CHECK (seen IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE site_snapshot_state (
    site_id TEXT PRIMARY KEY NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    latest_snapshot_id TEXT REFERENCES site_snapshots(id) ON DELETE SET NULL,
    baseline_snapshot_id TEXT REFERENCES site_snapshots(id) ON DELETE SET NULL,
    latest_snapshot_at TEXT,
    latest_change_count INTEGER NOT NULL DEFAULT 0 CHECK (latest_change_count >= 0),
    unseen_change_count INTEGER NOT NULL DEFAULT 0 CHECK (unseen_change_count >= 0),
    important_change_summary TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_site_snapshots_site_created
    ON site_snapshots(site_id, created_at DESC);
CREATE INDEX idx_site_snapshots_scan_run
    ON site_snapshots(scan_run_id);
CREATE INDEX idx_site_snapshots_site_source
    ON site_snapshots(site_id, source, created_at DESC);
CREATE INDEX idx_site_snapshots_maintenance
    ON site_snapshots(maintenance_run_id, source);
CREATE UNIQUE INDEX idx_site_snapshots_one_baseline
    ON site_snapshots(site_id) WHERE is_baseline=1;
CREATE UNIQUE INDEX idx_site_snapshots_scan_source
    ON site_snapshots(scan_run_id) WHERE scan_run_id IS NOT NULL AND source IN ('scan','baseline');

CREATE INDEX idx_snapshot_diffs_site_created
    ON snapshot_diffs(site_id, created_at DESC);
CREATE INDEX idx_snapshot_changes_site_to
    ON snapshot_changes(site_id, to_snapshot_id);
CREATE INDEX idx_snapshot_changes_to_category
    ON snapshot_changes(to_snapshot_id, category);
CREATE INDEX idx_snapshot_changes_site_type
    ON snapshot_changes(site_id, change_type, created_at DESC);
CREATE INDEX idx_snapshot_changes_site_seen
    ON snapshot_changes(site_id, seen, created_at DESC);
