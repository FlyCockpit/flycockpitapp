-- Codebase-intelligence outline index (GOALS §21, prompt
-- `codebase-intelligence-tools.md`). Project-scoped: every row carries
-- the project `root` so multi-project (§M6) is an additive change later.
-- Tables are prefixed `intel_` to avoid collisions in the shared cockpit
-- DB; column names mirror the build spec.
--
-- The index is on-demand (no file watcher): the central `index_target`
-- helper re-stats tracked files on each tool call and re-indexes
-- stale/removed ones before answering. `intel_files` is the parent;
-- the per-file tables FK to it ON DELETE CASCADE so dropping a deleted
-- or stale file's row purges its symbols/imports/identifiers/deps/
-- callsites in one statement — the deleted-file regression kcl hit
-- (forgetting to drop rows for removed files) cannot reproduce.

CREATE TABLE intel_files (
    root         TEXT NOT NULL,
    path         TEXT NOT NULL,
    language     TEXT NOT NULL,
    mtime_ns     INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    indexed_at   INTEGER NOT NULL,
    PRIMARY KEY (root, path)
);

CREATE TABLE intel_symbols (
    root       TEXT NOT NULL,
    path       TEXT NOT NULL,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    line       INTEGER NOT NULL,
    end_line   INTEGER NOT NULL,
    parent     TEXT,
    visibility TEXT,
    signature  TEXT,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_imports (
    root   TEXT NOT NULL,
    path   TEXT NOT NULL,
    target TEXT NOT NULL,
    line   INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_identifiers (
    root  TEXT NOT NULL,
    path  TEXT NOT NULL,
    token TEXT NOT NULL,
    line  INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

-- `importee` is NULL when the raw import target couldn't be resolved to
-- an indexed file (external crate, dynamic import, unresolved path).
CREATE TABLE intel_deps (
    root       TEXT NOT NULL,
    importer   TEXT NOT NULL,
    importee   TEXT,
    raw_target TEXT NOT NULL,
    line       INTEGER NOT NULL,
    FOREIGN KEY (root, importer) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

-- Populated on every index; consumed by the Phase-2 call-graph layer —
-- the `impact` tool and the `search`/`symbol_find` centrality ranking
-- (`src/intel/callgraph.rs`, migration 0038).
CREATE TABLE intel_callsites (
    root          TEXT NOT NULL,
    caller_file   TEXT NOT NULL,
    caller_line   INTEGER NOT NULL,
    caller_symbol TEXT,
    callee_name   TEXT NOT NULL,
    callee_kind   TEXT,
    FOREIGN KEY (root, caller_file) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

-- Covering lookups for the hot paths: symbol_find by name, word by
-- identifier token, deps/circular by importer/importee, and the
-- per-file cascade joins.
CREATE INDEX intel_symbols_name ON intel_symbols(name);
CREATE INDEX intel_symbols_file ON intel_symbols(root, path);
CREATE INDEX intel_identifiers_token ON intel_identifiers(token);
CREATE INDEX intel_identifiers_file ON intel_identifiers(root, path);
CREATE INDEX intel_imports_file ON intel_imports(root, path);
CREATE INDEX intel_deps_importer ON intel_deps(root, importer);
CREATE INDEX intel_deps_importee ON intel_deps(root, importee);
CREATE INDEX intel_callsites_callee ON intel_callsites(root, callee_name);
CREATE INDEX intel_callsites_file ON intel_callsites(root, caller_file);
