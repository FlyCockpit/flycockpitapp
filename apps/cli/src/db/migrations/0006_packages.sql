-- Cockpit-owned package registry (GOALS §3a docs agent, prompt
-- `docs-agent.md` decision 1). User-global, NOT project-scoped: the
-- docs agent answers questions about third-party dependencies whose
-- source clones are shared across every project on the device, so the
-- registry lives in the same global cockpit DB as `intel_*` but carries
-- no `project_id`.
--
-- Column shape started close to kcl's legacy `packages` table; newer
-- metadata such as manifest `prepare_scope` is added by later migrations.
-- We keep `source_url` indexed so Git packages dedupe by repo (a
-- monorepo cloned once is reused for every name that maps to it).
-- `source_type` is `'git'` or `'local'` (lowercase, matching kcl's
-- stored values).

CREATE TABLE packages (
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

-- Git packages dedupe by repo URL; this index backs the
-- lookup-by-source_url path used on add and import.
CREATE INDEX packages_source_url ON packages(source_url);
