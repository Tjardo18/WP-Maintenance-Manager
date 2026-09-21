ALTER TABLE sites ADD COLUMN parent_site_id TEXT REFERENCES sites(id) ON DELETE SET NULL;
ALTER TABLE sites ADD COLUMN relation_type TEXT CHECK (relation_type IN ('subdomain', 'subdirectory'));
ALTER TABLE sites ADD COLUMN parent_directory TEXT;

CREATE INDEX IF NOT EXISTS idx_sites_parent ON sites(parent_site_id, parent_directory);

CREATE TRIGGER IF NOT EXISTS sites_clear_orphaned_relation
AFTER UPDATE OF parent_site_id ON sites
WHEN NEW.parent_site_id IS NULL
  AND (NEW.relation_type IS NOT NULL OR NEW.parent_directory IS NOT NULL)
BEGIN
    UPDATE sites
    SET relation_type = NULL,
        parent_directory = NULL
    WHERE id = NEW.id;
END;
