//! Codebase-intelligence index (GOALS §21, Phase 1).
//!
//! A tree-sitter-backed outline cache living in cockpit's SQLite DB
//! (`intel_*` tables, migration 0005). The single on-demand chokepoint
//! is [`Index::ensure_fresh`]: every index-backed tool calls it first,
//! it re-stats the gitignore-walked file set, drops removed files (FK
//! cascade purges their children), and re-indexes new/stale ones —
//! parallel parse via rayon, serial chunked write through one
//! connection. No file watcher (the §M5 decision); a watcher's
//! silent-staleness failure mode loses to priority #1.
//!
//! Invalidation is cheap: `mtime_ns + size` first, SHA-256 only as a
//! tiebreaker when those moved (tolerates a touched-but-identical file).

pub mod budget;
pub mod callgraph;
pub mod lang;
pub mod resolve;
pub mod thin;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::intel::lang::{Extraction, Language};

/// Files at/above this size are recorded in `tree` but skipped for
/// parsing (no symbols/imports) — large generated files blow parse time
/// for no navigational value.
const LARGE_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Parse + write are batched in chunks of this many files to bound peak
/// memory (the kcl-proven size).
const CHUNK: usize = 200;

/// When the to-index set reaches this size, emit a one-shot cold-index
/// log so the first call doesn't look hung (the TUI shows a spinner on
/// ToolStart; this is the Phase-1 progress signal).
const COLD_THRESHOLD: usize = 100;

/// Project-scoped intelligence index over `root`.
pub struct Index {
    db: Db,
    root: PathBuf,
    /// Absolute `root` as the string stored in the `root` column.
    root_key: String,
    /// Effective gitignore read-allowlist globs
    /// (implementation note): gitignored-but-allowlisted
    /// paths the freshness walk re-includes so `search`/`tree`/`outline`/
    /// `symbol_find` surface them. Empty for the default constructor.
    gitignore_allow: Vec<String>,
}

/// A file as found on disk during the freshness scan.
#[derive(Clone)]
struct DiskFile {
    /// Relative, forward-slash path (the `path` column).
    rel: String,
    abs: PathBuf,
    language: Language,
    mtime_ns: i64,
    size: i64,
}

/// The parsed result for one file, ready for serial write.
struct ParsedFile {
    rel: String,
    language: Language,
    mtime_ns: i64,
    size: i64,
    lines: Option<i64>,
    content_hash: String,
    extraction: Extraction,
}

/// One symbol row for `outline` / `symbol_find`.
#[derive(Debug, Clone)]
pub struct SymbolRow {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub line: i64,
    pub end_line: i64,
    pub parent: Option<String>,
    pub visibility: Option<String>,
    pub signature: Option<String>,
}

/// Result of [`Index::outline_rows`]: a file's symbols, its `(target,
/// line)` imports, and its language label.
pub type OutlineData = (Vec<SymbolRow>, Vec<(String, i64)>, String);

/// One indexed file row for tree-style tools: path, language, size, lines, symbols.
pub type TreeRow = (String, String, i64, Option<i64>, i64);

/// A dependency edge for `deps` / `circular`.
#[derive(Debug, Clone)]
pub struct DepEdge {
    pub importer: String,
    pub importee: Option<String>,
    pub raw_target: String,
    pub line: i64,
}

impl Index {
    /// Build an index handle for `root` with no gitignore allowlist.
    pub fn new(db: Db, root: PathBuf) -> Self {
        let root_key = root.to_string_lossy().into_owned();
        Self {
            db,
            root,
            root_key,
            gitignore_allow: Vec::new(),
        }
    }

    /// Build an index handle for `root` whose freshness walk re-includes
    /// gitignored paths matching `gitignore_allow`
    /// (implementation note).
    pub fn with_allowlist(db: Db, root: PathBuf, gitignore_allow: Vec<String>) -> Self {
        let mut idx = Self::new(db, root);
        idx.gitignore_allow = gitignore_allow;
        idx
    }

    /// The single on-demand chokepoint. Re-stats the gitignore-walked
    /// file set, deletes removed files in one writer transaction, then
    /// re-indexes new/stale files. Disk walking, hashing, and parsing run
    /// off the DB writer; the writer only owns short metadata/chunk writes.
    pub async fn ensure_fresh(&self) -> Result<()> {
        let root = self.root.clone();
        let root_key = self.root_key.clone();
        let allow = self.gitignore_allow.clone();
        let disk = tokio::task::spawn_blocking(move || scan_disk(&root, &allow))
            .await
            .context("intel scan worker joined")??;
        let disk_paths: HashSet<String> = disk.iter().map(|d| d.rel.clone()).collect();

        let read_root_key = root_key.clone();
        let indexed = self
            .db
            .read(move |conn| load_indexed(conn, &read_root_key))
            .await?;
        let work = tokio::task::spawn_blocking(move || plan_fresh_work(disk, indexed))
            .await
            .context("intel planning worker joined")??;
        let removed_any = !work.removed.is_empty();

        if removed_any || !work.stat_updates.is_empty() {
            let write_root_key = root_key.clone();
            let removed = work.removed.clone();
            let stat_updates = work.stat_updates.clone();
            self.db
                .write(move |conn| {
                    apply_fresh_metadata(conn, &write_root_key, &removed, &stat_updates)
                })
                .await?;
        }

        if work.to_index.is_empty() {
            if removed_any {
                let write_root_key = root_key.clone();
                self.db
                    .write(move |conn| Ok(callgraph::recompute_centrality(conn, &write_root_key)?))
                    .await?;
            }
            return Ok(());
        }
        if work.to_index.len() >= COLD_THRESHOLD {
            tracing::info!(files = work.to_index.len(), "intel: cold-indexing");
        }

        let module_root = self.root.clone();
        let module_prefix = tokio::task::spawn_blocking(move || go_module_prefix(&module_root))
            .await
            .context("intel module-prefix worker joined")?;
        let now = now_secs();
        for chunk in work.to_index.chunks(CHUNK) {
            let chunk = chunk.to_vec();
            let parsed = tokio::task::spawn_blocking(move || parse_files_capped(chunk))
                .await
                .context("intel parse worker joined")??;
            let write_root_key = root_key.clone();
            let write_disk_paths = disk_paths.clone();
            let write_module_prefix = module_prefix.clone();
            self.db
                .write(move |conn| {
                    write_chunk(
                        conn,
                        &write_root_key,
                        &write_disk_paths,
                        &write_module_prefix,
                        &parsed,
                        now,
                    )
                })
                .await?;
        }

        let write_root_key = root_key.clone();
        self.db
            .write(move |conn| Ok(callgraph::recompute_centrality(conn, &write_root_key)?))
            .await?;
        Ok(())
    }

    // ---- query methods (each assumes ensure_fresh already ran) --------

    /// All known files for `tree`, ordered by path. Large files are indexed
    /// for visibility but carry no stored line count.
    pub fn tree_rows(&self) -> Result<Vec<TreeRow>> {
        let root_key = self.root_key.clone();
        self.db.read_blocking(|conn| {
            let mut stmt = conn.prepare(
                "SELECT f.path, f.language, f.size, f.lines, COUNT(s.name) \
                 FROM intel_files f \
                 LEFT JOIN intel_symbols s ON s.root = f.root AND s.path = f.path \
                 WHERE f.root = ?1 \
                 GROUP BY f.root, f.path, f.language, f.size, f.lines \
                 ORDER BY f.path",
            )?;
            let rows = stmt
                .query_map([&root_key], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Symbols + imports for one file, ordered by line (for `outline`).
    pub fn outline_rows(&self, rel: &str) -> Result<OutlineData> {
        let root_key = self.root_key.clone();
        let rel_owned = rel.to_string();
        self.db.read_blocking(|conn| {
            let language: Option<String> = conn
                .query_row(
                    "SELECT language FROM intel_files WHERE root = ?1 AND path = ?2",
                    rusqlite::params![root_key, rel_owned],
                    |r| r.get(0),
                )
                .ok();
            let symbols = query_symbols(
                conn,
                &root_key,
                "SELECT path, name, kind, line, end_line, parent, visibility, signature \
                 FROM intel_symbols WHERE root = ?1 AND path = ?2 ORDER BY line",
                rusqlite::params![root_key, rel_owned],
            )?;
            let mut stmt = conn.prepare(
                "SELECT target, line FROM intel_imports WHERE root = ?1 AND path = ?2 ORDER BY line",
            )?;
            let imports = stmt
                .query_map(rusqlite::params![root_key, rel_owned], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((symbols, imports, language.unwrap_or_default()))
        })
    }

    /// Find symbols by name. `exact` toggles `=` vs prefix `LIKE`;
    /// optional `kind` filters by symbol kind.
    pub fn symbol_find(
        &self,
        name: &str,
        exact: bool,
        kind: Option<&str>,
    ) -> Result<Vec<SymbolRow>> {
        let root_key = self.root_key.clone();
        let name = name.to_string();
        let kind = kind.map(|s| s.to_string());
        self.db.read_blocking(|conn| {
            let base = "SELECT path, name, kind, line, end_line, parent, visibility, signature \
                 FROM intel_symbols WHERE root = ?1 AND ";
            if exact {
                let sql = format!(
                    "{base} name = ?2 {} ORDER BY path, line",
                    kind_clause(&kind, 3)
                );
                let rows = run_symbol_query(conn, &sql, &root_key, &name, kind.as_deref())?;
                Ok(rows)
            } else {
                // Prefix match; escape LIKE metacharacters.
                let pattern = format!("{}%", escape_like(&name));
                let sql = format!(
                    "{base} name LIKE ?2 ESCAPE '\\' {} ORDER BY path, line",
                    kind_clause(&kind, 3)
                );
                let rows = run_symbol_query(conn, &sql, &root_key, &pattern, kind.as_deref())?;
                Ok(rows)
            }
        })
    }

    /// Identifier occurrences for `word`, grouped by file. `case_insensitive`
    /// matches with `COLLATE NOCASE`.
    pub fn word_hits(
        &self,
        token: &str,
        case_insensitive: bool,
    ) -> Result<Vec<(String, Vec<i64>)>> {
        let root_key = self.root_key.clone();
        let token = token.to_string();
        self.db.read_blocking(|conn| {
            let sql = if case_insensitive {
                "SELECT path, line FROM intel_identifiers \
                 WHERE root = ?1 AND token = ?2 COLLATE NOCASE ORDER BY path, line"
            } else {
                "SELECT path, line FROM intel_identifiers \
                 WHERE root = ?1 AND token = ?2 ORDER BY path, line"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt
                .query_map(rusqlite::params![root_key, token], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut grouped: Vec<(String, Vec<i64>)> = Vec::new();
            for (path, line) in rows {
                match grouped.last_mut() {
                    Some((p, lines)) if *p == path => lines.push(line),
                    _ => grouped.push((path, vec![line])),
                }
            }
            Ok(grouped)
        })
    }

    /// All dependency edges for the project (`deps` / `circular`).
    pub fn dep_edges(&self) -> Result<Vec<DepEdge>> {
        let root_key = self.root_key.clone();
        self.db.read_blocking(|conn| {
            let mut stmt = conn.prepare(
                "SELECT importer, importee, raw_target, line FROM intel_deps \
                 WHERE root = ?1 ORDER BY importer, line",
            )?;
            let rows = stmt
                .query_map([&root_key], |r| {
                    Ok(DepEdge {
                        importer: r.get(0)?,
                        importee: r.get(1)?,
                        raw_target: r.get(2)?,
                        line: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// The materialized per-file centrality scores for this project
    /// (`callgraph::load_centrality`). An absent/empty table yields an
    /// empty map, which the ranking treats as no signal (unranked order).
    pub fn centrality_scores(&self) -> Result<HashMap<String, f64>> {
        let root_key = self.root_key.clone();
        self.db
            .read_blocking(|conn| Ok(callgraph::load_centrality(conn, &root_key)?))
    }

    /// Resolve `name` (+ optional `path`/`kind` disambiguators, matching
    /// `symbol_find`'s exact-match conventions) to the target symbol(s)
    /// for the `impact` tool, returning each as `(path, line, kind)`.
    pub fn impact_targets(
        &self,
        name: &str,
        path: Option<&str>,
        kind: Option<&str>,
    ) -> Result<Vec<(String, i64, String)>> {
        let root_key = self.root_key.clone();
        let name = name.to_string();
        let path = path.map(|s| s.to_string());
        let kind = kind.map(|s| s.to_string());
        self.db.read_blocking(|conn| {
            let mut sql = String::from(
                "SELECT path, line, kind FROM intel_symbols WHERE root = ?1 AND name = ?2",
            );
            let mut params: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(root_key.clone()), Box::new(name.clone())];
            if let Some(p) = &path {
                params.push(Box::new(p.clone()));
                sql.push_str(&format!(" AND path = ?{}", params.len()));
            }
            if let Some(k) = &kind {
                params.push(Box::new(k.clone()));
                sql.push_str(&format!(" AND kind = ?{}", params.len()));
            }
            sql.push_str(" ORDER BY path, line");
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt
                .query_map(param_refs.as_slice(), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Callers of `target` for the `impact` tool: every `intel_callsites`
    /// row whose `callee_name` resolves **high-precision** (exactly one
    /// definition) to `(target_path, target_line)`. Returns
    /// `(caller_file, caller_line, caller_symbol)`. Ambiguous/unresolved
    /// callsites and denylisted names are omitted (never guessed).
    pub fn impact_callers(
        &self,
        target_path: &str,
        target_line: i64,
    ) -> Result<Vec<(String, i64, Option<String>)>> {
        let root_key = self.root_key.clone();
        let target_path = target_path.to_string();
        self.db.read_blocking(|conn| {
            // Only callsites naming `target` can possibly resolve to it —
            // restrict by the (root, callee_name) index. The target's own
            // name is what an incoming call writes.
            let name: String = conn.query_row(
                "SELECT name FROM intel_symbols WHERE root = ?1 AND path = ?2 AND line = ?3 LIMIT 1",
                rusqlite::params![root_key, target_path, target_line],
                |r| r.get(0),
            )?;
            let mut stmt = conn.prepare(
                "SELECT caller_file, caller_line, caller_symbol, callee_kind \
                 FROM intel_callsites WHERE root = ?1 AND callee_name = ?2 \
                 ORDER BY caller_file, caller_line",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![root_key, name], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::new();
            for (caller_file, caller_line, caller_symbol, callee_kind) in rows {
                let defs = callgraph::resolve_defs(conn, &root_key, &name, callee_kind.as_deref())?;
                // High-precision omit: exactly one def, and it is `target`.
                if defs.len() == 1 && defs[0].0 == target_path && defs[0].1 == target_line {
                    out.push((caller_file, caller_line, caller_symbol));
                }
            }
            Ok(out)
        })
    }

    /// Outgoing calls from `target`'s body for the `impact` tool: every
    /// `intel_callsites` row where `caller_symbol = target_name`, each
    /// resolved **high-precision** (exactly one definition) to its callee.
    /// Returns `(callee_name, def_file, def_line)`. Ambiguous/unresolved
    /// callees and denylisted names are omitted.
    pub fn impact_calls(&self, target_name: &str) -> Result<Vec<(String, String, i64)>> {
        let root_key = self.root_key.clone();
        let target_name = target_name.to_string();
        self.db.read_blocking(|conn| {
            let mut stmt = conn.prepare(
                "SELECT callee_name, callee_kind FROM intel_callsites \
                 WHERE root = ?1 AND caller_symbol = ?2 ORDER BY callee_name",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![root_key, target_name], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::new();
            let mut seen: HashSet<(String, String, i64)> = HashSet::new();
            for (callee_name, callee_kind) in rows {
                let defs =
                    callgraph::resolve_defs(conn, &root_key, &callee_name, callee_kind.as_deref())?;
                if defs.len() == 1 {
                    let (def_file, def_line) = defs.into_iter().next().unwrap();
                    let row = (callee_name.clone(), def_file, def_line);
                    if seen.insert(row.clone()) {
                        out.push(row);
                    }
                }
            }
            out.sort();
            Ok(out)
        })
    }
}

fn kind_clause(kind: &Option<String>, idx: usize) -> String {
    if kind.is_some() {
        format!("AND kind = ?{idx}")
    } else {
        String::new()
    }
}

fn run_symbol_query(
    conn: &Connection,
    sql: &str,
    root_key: &str,
    name_or_pattern: &str,
    kind: Option<&str>,
) -> rusqlite::Result<Vec<SymbolRow>> {
    if let Some(k) = kind {
        query_symbols(
            conn,
            root_key,
            sql,
            rusqlite::params![root_key, name_or_pattern, k],
        )
    } else {
        query_symbols(
            conn,
            root_key,
            sql,
            rusqlite::params![root_key, name_or_pattern],
        )
    }
}

fn query_symbols(
    conn: &Connection,
    _root_key: &str,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<Vec<SymbolRow>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(params, |r| {
            Ok(SymbolRow {
                path: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                line: r.get(3)?,
                end_line: r.get(4)?,
                parent: r.get(5)?,
                visibility: r.get(6)?,
                signature: r.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Escape `%`, `_` and `\` for a `LIKE … ESCAPE '\'` prefix match.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ---- the freshness chokepoint ---------------------------------------------

struct FreshWork {
    removed: Vec<String>,
    stat_updates: Vec<DiskFile>,
    to_index: Vec<DiskFile>,
}

fn plan_fresh_work(disk: Vec<DiskFile>, indexed: IndexedMap) -> Result<FreshWork> {
    let disk_paths: HashSet<String> = disk.iter().map(|d| d.rel.clone()).collect();
    let removed = indexed
        .keys()
        .filter(|p| !disk_paths.contains(*p))
        .cloned()
        .collect();
    let mut stat_updates = Vec::new();
    let mut to_index = Vec::new();
    for f in disk {
        match indexed.get(&f.rel) {
            None => to_index.push(f),
            Some((mtime, size, hash)) => {
                if *mtime == f.mtime_ns && *size == f.size {
                    continue;
                }
                if f.size as u64 >= LARGE_FILE_BYTES {
                    to_index.push(f);
                    continue;
                }
                match hash_file(&f.abs) {
                    Ok(h) if &h == hash => stat_updates.push(f),
                    _ => to_index.push(f),
                }
            }
        }
    }
    Ok(FreshWork {
        removed,
        stat_updates,
        to_index,
    })
}

fn apply_fresh_metadata(
    conn: &Connection,
    root_key: &str,
    removed: &[String],
    stat_updates: &[DiskFile],
) -> Result<()> {
    if removed.is_empty() && stat_updates.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut del = tx.prepare("DELETE FROM intel_files WHERE root = ?1 AND path = ?2")?;
        for path in removed {
            del.execute(rusqlite::params![root_key, path])?;
        }
    }
    {
        let mut update = tx.prepare(
            "UPDATE intel_files SET mtime_ns = ?3, size = ?4 WHERE root = ?1 AND path = ?2",
        )?;
        for f in stat_updates {
            update.execute(rusqlite::params![root_key, f.rel, f.mtime_ns, f.size])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn intel_parse_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_sub(1)
        .max(1)
}

fn parse_files_capped(files: Vec<DiskFile>) -> Result<Vec<ParsedFile>> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(intel_parse_threads())
        .build()
        .context("building intel parse pool")?;
    Ok(pool.install(|| {
        files
            .par_iter()
            .filter_map(|f| parse_one(f).ok().flatten())
            .collect()
    }))
}

/// Walk `root` gitignore-aware and stat every regular file. Any gitignored
/// path matching `gitignore_allow` (the read-allowlist) is re-included via a
/// supplementary gitignore-off pass, so allowlisted-but-gitignored files
/// surface in `search`/`tree`/`outline`/`symbol_find`
/// (implementation note).
fn scan_disk(root: &Path, gitignore_allow: &[String]) -> Result<Vec<DiskFile>> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .require_git(false)
        .follow_links(false);
    for dent in walker.build().flatten() {
        if !dent.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        if let Some(df) = disk_file_for(dent.path(), root) {
            seen.insert(df.rel.clone());
            out.push(df);
        }
    }

    // Re-include allowlisted-but-gitignored paths: a second pass with
    // gitignore filtering OFF, keeping only entries the allowlist re-permits
    // (and not already surfaced above). The allowlist matcher anchors at
    // `root`, identical to the read gate's matching root.
    if !gitignore_allow.is_empty() {
        let matcher = crate::gitignore::build_allowlist_matcher(root, gitignore_allow);
        if !matcher.is_empty() {
            let mut wide = WalkBuilder::new(root);
            wide.hidden(false)
                .git_ignore(false)
                .git_global(false)
                .git_exclude(false)
                .parents(false)
                .require_git(false)
                .follow_links(false);
            // Skip the `.git` dir explicitly (gitignore-off walks descend it).
            wide.filter_entry(|dent| dent.file_name() != ".git");
            for dent in wide.build().flatten() {
                if !dent.file_type().is_some_and(|t| t.is_file()) {
                    continue;
                }
                let abs = dent.path();
                if !crate::gitignore::allowlist_matches(abs, root, gitignore_allow) {
                    continue;
                }
                if let Some(df) = disk_file_for(abs, root)
                    && seen.insert(df.rel.clone())
                {
                    out.push(df);
                }
            }
        }
    }
    Ok(out)
}

/// Build a [`DiskFile`] for `abs` relative to `root`, or `None` when it can't
/// be related to `root` / stat'd.
fn disk_file_for(abs: &Path, root: &Path) -> Option<DiskFile> {
    let rel = abs.strip_prefix(root).ok()?;
    let rel = rel.to_string_lossy().replace('\\', "/");
    let meta = std::fs::metadata(abs).ok()?;
    Some(DiskFile {
        rel,
        language: Language::from_path(abs),
        mtime_ns: mtime_ns(&meta),
        size: meta.len() as i64,
        abs: abs.to_path_buf(),
    })
}

type IndexedMap = HashMap<String, (i64, i64, String)>;

fn load_indexed(conn: &Connection, root_key: &str) -> Result<IndexedMap> {
    let mut stmt =
        conn.prepare("SELECT path, mtime_ns, size, content_hash FROM intel_files WHERE root = ?1")?;
    let rows = stmt
        .query_map([root_key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    Ok(rows)
}

/// Read + parse one file off the executor (rayon worker). Returns
/// `Ok(None)` for binary files (skipped). Large files are still recorded
/// (`tree` visibility) but parsed to an empty extraction.
fn parse_one(f: &DiskFile) -> Result<Option<ParsedFile>> {
    if f.size as u64 >= LARGE_FILE_BYTES {
        return Ok(Some(ParsedFile {
            rel: f.rel.clone(),
            language: f.language,
            mtime_ns: f.mtime_ns,
            size: f.size,
            lines: None,
            content_hash: String::new(),
            extraction: Extraction::default(),
        }));
    }
    let bytes = std::fs::read(&f.abs).with_context(|| format!("reading {}", f.abs.display()))?;
    // Binary files: skip entirely (no index row) — `tree` reads the FS
    // for those via the same gitignore walk in the tool, and `read`
    // already detects binaries.
    if crate::tools::common::looks_binary(&bytes) {
        return Ok(None);
    }
    let lines = Some(line_count_bytes(&bytes) as i64);
    let content_hash = hash_bytes(&bytes);
    let extraction = lang::extract(f.language, &bytes).unwrap_or_default();
    Ok(Some(ParsedFile {
        rel: f.rel.clone(),
        language: f.language,
        mtime_ns: f.mtime_ns,
        size: f.size,
        lines,
        content_hash,
        extraction,
    }))
}

/// Serial write of one parsed chunk in a single transaction. Replaces
/// each file's rows (delete-then-insert) so a re-index is idempotent;
/// the parent delete cascades children, then we re-insert everything.
fn write_chunk(
    conn: &Connection,
    root_key: &str,
    existing: &HashSet<String>,
    module_prefix: &str,
    parsed: &[ParsedFile],
    now: i64,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        let mut del = tx.prepare("DELETE FROM intel_files WHERE root = ?1 AND path = ?2")?;
        let mut ins_file = tx.prepare(
            "INSERT INTO intel_files (root, path, language, mtime_ns, size, lines, content_hash, indexed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        let mut ins_sym = tx.prepare(
            "INSERT INTO intel_symbols (root, path, name, kind, line, end_line, parent, visibility, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        let mut ins_imp = tx.prepare(
            "INSERT INTO intel_imports (root, path, target, line) VALUES (?1, ?2, ?3, ?4)",
        )?;
        let mut ins_id = tx.prepare(
            "INSERT INTO intel_identifiers (root, path, token, line) VALUES (?1, ?2, ?3, ?4)",
        )?;
        let mut ins_dep = tx.prepare(
            "INSERT INTO intel_deps (root, importer, importee, raw_target, line) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let mut ins_call = tx.prepare(
            "INSERT INTO intel_callsites (root, caller_file, caller_line, caller_symbol, callee_name, callee_kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        for p in parsed {
            del.execute(rusqlite::params![root_key, p.rel])?;
            ins_file.execute(rusqlite::params![
                root_key,
                p.rel,
                p.language.as_str(),
                p.mtime_ns,
                p.size,
                p.lines,
                p.content_hash,
                now
            ])?;
            for s in &p.extraction.symbols {
                ins_sym.execute(rusqlite::params![
                    root_key,
                    p.rel,
                    s.name,
                    s.kind,
                    s.line,
                    s.end_line,
                    s.parent,
                    s.visibility,
                    s.signature
                ])?;
            }
            for imp in &p.extraction.imports {
                ins_imp.execute(rusqlite::params![root_key, p.rel, imp.target, imp.line])?;
                let importee =
                    resolve::resolve(p.language, &p.rel, &imp.target, existing, module_prefix);
                ins_dep.execute(rusqlite::params![
                    root_key, p.rel, importee, imp.target, imp.line
                ])?;
            }
            for id in &p.extraction.identifiers {
                ins_id.execute(rusqlite::params![root_key, p.rel, id.token, id.line])?;
            }
            for cs in &p.extraction.callsites {
                ins_call.execute(rusqlite::params![
                    root_key,
                    p.rel,
                    cs.caller_line,
                    cs.caller_symbol,
                    cs.callee_name,
                    cs.callee_kind
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

// ---- small helpers ---------------------------------------------------------

fn line_count_bytes(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let nl = bytes.iter().filter(|&&c| c == b'\n').count();
    if bytes.last() == Some(&b'\n') {
        nl
    } else {
        nl + 1
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(hash_bytes(&bytes))
}

/// Lowercase hex of a byte slice (no `hex` crate dependency).
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn mtime_ns(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read the `module` line out of `go.mod` at the project root, if any.
fn go_module_prefix(root: &Path) -> String {
    let gomod = root.join("go.mod");
    let Ok(text) = std::fs::read_to_string(&gomod) else {
        return String::new();
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("module ") {
            return rest.trim().to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn parse_pool_leaves_interactive_headroom() {
        let cores = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let expected = cores.saturating_sub(1).max(1);
        assert_eq!(intel_parse_threads(), expected);
        assert!(intel_parse_threads() <= cores.max(1));
    }

    #[test]
    fn parse_one_large_file_skips_read_and_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("huge.rs");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(LARGE_FILE_BYTES + 1)
            .unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let file = DiskFile {
            rel: "huge.rs".to_string(),
            language: Language::Rust,
            mtime_ns: mtime_ns(&meta),
            size: meta.len() as i64,
            abs: path,
        };

        let parsed = parse_one(&file).unwrap().unwrap();

        assert_eq!(parsed.rel, "huge.rs");
        assert_eq!(parsed.size, (LARGE_FILE_BYTES + 1) as i64);
        assert!(parsed.lines.is_none());
        assert!(parsed.content_hash.is_empty());
        assert!(parsed.extraction.symbols.is_empty());
        assert!(parsed.extraction.imports.is_empty());
        assert!(parsed.extraction.identifiers.is_empty());
        assert!(parsed.extraction.callsites.is_empty());
    }

    #[test]
    fn parse_one_stores_count_lines_semantics_for_indexed_files() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lines.rs");
        let body = b"pub fn one() {}\npub fn two() {}\npartial";
        std::fs::write(&path, body).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let file = DiskFile {
            rel: "lines.rs".to_string(),
            language: Language::Rust,
            mtime_ns: mtime_ns(&meta),
            size: meta.len() as i64,
            abs: path,
        };

        let parsed = parse_one(&file).unwrap().unwrap();

        assert_eq!(parsed.lines, Some(line_count_bytes(body) as i64));
        assert_eq!(parsed.lines, Some(3));
    }

    fn count_rows(db: &Db, table: &str, root_key: &str, path: &str) -> i64 {
        db.read_blocking(|conn| {
            let sql = format!("SELECT COUNT(*) FROM {table} WHERE root = ?1 AND path = ?2");
            Ok(conn.query_row(&sql, rusqlite::params![root_key, path], |r| r.get(0))?)
        })
        .unwrap()
    }

    #[tokio::test]
    async fn indexes_two_languages() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write_file(&root, "src/lib.rs", "pub struct Foo;\npub fn bar() {}\n");
        write_file(
            &root,
            "app.py",
            "def baz():\n    pass\nclass Qux:\n    pass\n",
        );

        let index = Index::new(db.clone(), root.clone());
        index.ensure_fresh().await.unwrap();

        let rust = index.symbol_find("Foo", true, None).unwrap();
        assert_eq!(rust.len(), 1, "expected Rust struct Foo");
        let py = index.symbol_find("Qux", true, None).unwrap();
        assert_eq!(py.len(), 1, "expected Python class Qux");

        let tree = index.tree_rows().unwrap();
        assert!(tree.iter().any(|(p, _, _, _, _)| p == "src/lib.rs"));
        assert!(tree.iter().any(|(p, _, _, _, _)| p == "app.py"));
    }

    /// A gitignored source file is skipped by the default walk, but
    /// re-included once the read-allowlist matches it
    /// (implementation note).
    #[tokio::test]
    async fn allowlist_reincludes_gitignored_file() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write_file(&root, ".gitignore", "generated/\n");
        write_file(&root, "src/lib.rs", "pub fn keep() {}\n");
        write_file(&root, "generated/out.rs", "pub fn gen() {}\n");

        // No allowlist → the gitignored file is absent from the index.
        let bare = Index::new(db.clone(), root.clone());
        bare.ensure_fresh().await.unwrap();
        assert!(
            bare.symbol_find("gen", true, None).unwrap().is_empty(),
            "gitignored file must not index by default"
        );

        // With `generated/` allowlisted, it is re-included and surfaces.
        let allowed =
            Index::with_allowlist(db.clone(), root.clone(), vec!["generated/".to_string()]);
        allowed.ensure_fresh().await.unwrap();
        assert_eq!(
            allowed.symbol_find("gen", true, None).unwrap().len(),
            1,
            "allowlisted gitignored file must index"
        );
        // The tracked file still indexes too.
        assert_eq!(allowed.symbol_find("keep", true, None).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deleted_file_leaves_no_stale_rows() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let root_key = root.to_string_lossy().into_owned();
        write_file(&root, "a.rs", "pub fn alpha() {}\n");
        write_file(&root, "b.rs", "pub fn beta() {}\n");

        let index = Index::new(db.clone(), root.clone());
        index.ensure_fresh().await.unwrap();
        assert_eq!(count_rows(&db, "intel_symbols", &root_key, "a.rs"), 1);

        // Edit a.rs (add a symbol) then DELETE b.rs.
        write_file(&root, "a.rs", "pub fn alpha() {}\npub fn alpha2() {}\n");
        std::fs::remove_file(root.join("b.rs")).unwrap();
        index.ensure_fresh().await.unwrap();

        // b.rs: no stale file or symbol rows.
        assert_eq!(count_rows(&db, "intel_files", &root_key, "b.rs"), 0);
        assert_eq!(count_rows(&db, "intel_symbols", &root_key, "b.rs"), 0);
        // a.rs: re-indexed to 2 symbols.
        assert_eq!(count_rows(&db, "intel_symbols", &root_key, "a.rs"), 2);
    }

    #[tokio::test]
    async fn centrality_reflects_an_edit_after_reindex() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        // `target` is defined once; `caller` calls it zero times initially.
        write_file(&root, "lib.rs", "pub fn target() {}\npub fn caller() {}\n");
        let index = Index::new(db.clone(), root.clone());
        index.ensure_fresh().await.unwrap();

        // No callsite to `target` yet → lib.rs has zero in-degree weight.
        let before = index.centrality_scores().unwrap();
        let before_score = before.get("lib.rs").copied().unwrap_or(0.0);
        assert_eq!(before_score, 0.0, "no calls yet, got {before:?}");

        // Edit the file to add a real call to `target`, then re-index.
        write_file(
            &root,
            "lib.rs",
            "pub fn target() {}\npub fn caller() {\n    target();\n}\n",
        );
        index.ensure_fresh().await.unwrap();

        // Centrality now reflects the new edge — no stale zero.
        let after = index.centrality_scores().unwrap();
        let after_score = after.get("lib.rs").copied().unwrap_or(0.0);
        assert!(
            after_score > before_score,
            "centrality must reflect the new call after re-index; before={before_score}, after={after_score}, map={after:?}"
        );
    }

    #[tokio::test]
    async fn centrality_recomputes_after_a_file_is_removed() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write_file(&root, "lib.rs", "pub fn target() {}\n");
        write_file(&root, "caller.rs", "pub fn c() {\n    target();\n}\n");
        let index = Index::new(db.clone(), root.clone());
        index.ensure_fresh().await.unwrap();
        let with_caller = index
            .centrality_scores()
            .unwrap()
            .get("lib.rs")
            .copied()
            .unwrap_or(0.0);
        assert!(with_caller > 0.0, "target should be called once");

        // Delete the only caller; the score must drop (no stale edge).
        std::fs::remove_file(root.join("caller.rs")).unwrap();
        index.ensure_fresh().await.unwrap();
        let after = index
            .centrality_scores()
            .unwrap()
            .get("lib.rs")
            .copied()
            .unwrap_or(0.0);
        assert_eq!(after, 0.0, "removed caller's edge must not persist");
    }

    #[tokio::test]
    async fn unchanged_file_is_a_cache_hit() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write_file(&root, "x.rs", "pub fn x() {}\n");
        let index = Index::new(db.clone(), root.clone());
        index.ensure_fresh().await.unwrap();
        // Second pass with no changes must not error or duplicate rows.
        index.ensure_fresh().await.unwrap();
        let hits = index.symbol_find("x", true, None).unwrap();
        assert_eq!(hits.len(), 1);
    }
}
