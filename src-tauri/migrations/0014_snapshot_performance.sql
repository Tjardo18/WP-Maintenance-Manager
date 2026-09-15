CREATE INDEX idx_snapshot_diffs_to_created
    ON snapshot_diffs(to_snapshot_id, created_at DESC);

CREATE INDEX idx_snapshot_changes_to_severity_seen
    ON snapshot_changes(to_snapshot_id, severity, seen, created_at DESC);
