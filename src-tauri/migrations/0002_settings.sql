CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO app_settings(key, value, updated_at)
VALUES('scan_concurrency', '4', CURRENT_TIMESTAMP);
