-- Store kcl package preparation scope imported from the portable
-- `kcl packages export` manifest. Existing rows default to global,
-- matching old kcl DB rows and cockpit's current behavior.
--
-- Some migration repair tests intentionally build partial historical
-- schemas around later session tables, so keep this migration robust
-- when the old packages table is absent.
CREATE TABLE IF NOT EXISTS packages (
    id            TEXT PRIMARY KEY,
    identifier    TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    source_type   TEXT NOT NULL,
    source_url    TEXT,
    source_branch TEXT,
    path          TEXT NOT NULL,
    shallow       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS packages_source_url ON packages(source_url);

ALTER TABLE packages
ADD COLUMN prepare_scope TEXT NOT NULL DEFAULT 'global';
