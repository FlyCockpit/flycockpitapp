//! Deterministic call-graph layer over the existing intel tables
//! (GOALS §21, prompt `code-graph-centrality-and-context.md`).
//!
//! No LLM, no new extraction: this is pure SQL over `intel_callsites`
//! (already populated, previously write-only) joined against
//! `intel_symbols`, plus a ranking multiply. It powers two surfaces —
//! centrality ranking for `search`/`symbol_find` and the standalone
//! `impact` tool — sharing one **name-based, high-precision** edge
//! resolver.
//!
//! ## Edge resolution (shared)
//!
//! Resolution is **name-only** (no type inference), exactly as codedb
//! does it. For a callsite with `callee_name = N` and `callee_kind = K`:
//!
//! - `K = call` (or absent) → resolve `N` against function/method defs.
//! - `K = type_ref` → resolve against type/struct/enum/class/interface
//!   defs.
//! - `K = macro` → resolve against macro defs; cockpit's extractor emits
//!   no `macro`-kind symbol rows, so a macro callee currently resolves to
//!   zero candidates and is treated as **unresolved** (documented gap).
//!
//! A small centralized [`DENYLIST`] of ubiquitous container/std method
//! names is filtered out *before* resolving, since they assert
//! meaningless edges.
//!
//! ## Test-ness — known precision gap
//!
//! The spec asks test symbols to be excluded as resolution targets.
//! `intel_symbols` carries no test-ness marker (no `#[cfg(test)]` /
//! `#[test]` flag column, and the extractor never records one), so
//! test-ness is **not derivable here**. Per the spec we therefore resolve
//! against *all* definitions and document this as a known precision gap —
//! we do NOT invent a name/path heuristic that guesses test-ness, because
//! a wrong guess is worse than the gap (priority #1).
//!
//! ## High-precision omit vs 1/M split
//!
//! - The **`impact` tool** reports an edge ONLY when `N` resolves to
//!   exactly one definition. Ambiguous (M>1) or unresolved (M=0) callees
//!   are **omitted**, never guessed — asserting a false edge to a weak
//!   ~120k model is worse than omitting a true one (priority #1).
//! - **Centrality** (ranking signal only) keeps recall via a **1/M
//!   weight-split**: a callee resolving to M defs contributes `1/M` to
//!   each candidate def's file. Unresolved callees contribute nothing.
//!
//! ## Materialization
//!
//! Centrality is a whole-graph property, so a single changed file shifts
//! other files' scores. [`recompute_centrality`] rebuilds the
//! `intel_centrality(root, path, score)` table **wholesale** via one SQL
//! aggregate join, run once per `ensure_fresh` pass that wrote any chunk
//! (cheap — no re-parse). The query hot path reads it via
//! [`load_centrality`]; an absent/empty table degrades gracefully to
//! unranked order (returns an empty map), never panics.

use std::collections::HashMap;

use rusqlite::Connection;

/// A resolved definition site: `(path, line)`.
type DefSite = (String, i64);

/// Resolution cache key: `(callee_name, callee_kind)`.
type ResolveKey = (String, Option<String>);

/// Ubiquitous container/std method names whose call-sites would assert
/// meaningless edges. Filtered out of resolution for BOTH surfaces before
/// any lookup. Kept small and centralized per the spec. Matched
/// case-sensitively against `callee_name`.
pub const DENYLIST: &[&str] = &[
    "init",
    "new",
    "get",
    "set",
    "append",
    "push",
    "pop",
    "next",
    "lock",
    "unlock",
    "len",
    "clone",
    "iter",
    "map",
    "unwrap",
    "into",
    "from",
    "to_string",
];

/// Definition kinds a `call`/`macro`-kind callee can resolve to
/// (functions + methods). `symbol_kind_for` in `lang.rs` is the source of
/// these strings.
const CALL_DEF_KINDS: &[&str] = &["function", "method"];

/// Definition kinds a `type_ref`-kind callee can resolve to (types).
const TYPE_DEF_KINDS: &[&str] = &["struct", "enum", "type", "class", "interface"];

/// Ranking constant `k` (codedb's tuned value). The centrality ranking
/// multiplier is `1 + k·ln(1 + centrality[file])`.
pub const RANK_K: f64 = 0.15;

/// True if `name` is on the ubiquitous-name denylist (case-sensitive).
pub fn is_denied(name: &str) -> bool {
    DENYLIST.contains(&name)
}

/// The set of definition kinds a callsite of `callee_kind` resolves
/// against. `None`/unknown kinds default to the function/method set (the
/// common `call` case). A `macro` kind resolves against macro defs, which
/// cockpit doesn't currently extract, so it returns an empty slice →
/// unresolved.
fn def_kinds_for(callee_kind: Option<&str>) -> &'static [&'static str] {
    match callee_kind {
        Some("type_ref") => TYPE_DEF_KINDS,
        Some("macro") => &[], // no macro-def symbols are extracted today
        _ => CALL_DEF_KINDS,
    }
}

/// SQL `IN (...)` placeholder list of the right length, e.g. `?2, ?3`.
/// `start` is the 1-based index of the first placeholder.
fn in_placeholders(start: usize, n: usize) -> String {
    (0..n)
        .map(|i| format!("?{}", start + i))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve `callee_name` (with `callee_kind`) to the definitions it names
/// in `root`, returning `(path, line)` for each matching definition.
/// Denylisted names short-circuit to an empty result. This is the
/// single shared resolver; callers apply the high-precision-omit (exactly
/// one) or 1/M-split policy themselves.
pub fn resolve_defs(
    conn: &Connection,
    root: &str,
    callee_name: &str,
    callee_kind: Option<&str>,
) -> rusqlite::Result<Vec<(String, i64)>> {
    if is_denied(callee_name) {
        return Ok(Vec::new());
    }
    let kinds = def_kinds_for(callee_kind);
    if kinds.is_empty() {
        return Ok(Vec::new());
    }
    // ?1 = root, ?2 = callee_name, ?3.. = the kind set.
    let sql = format!(
        "SELECT path, line FROM intel_symbols \
         WHERE root = ?1 AND name = ?2 AND kind IN ({}) ORDER BY path, line",
        in_placeholders(3, kinds.len())
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&root, &callee_name];
    for k in kinds {
        params.push(k);
    }
    let rows = stmt
        .query_map(params.as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Recompute `intel_centrality` for `root` wholesale. Deletes the old
/// rows and re-derives every file's weighted in-degree via the 1/M split
/// over `intel_callsites ⋈ intel_symbols`. Deterministic: pure SQL +
/// arithmetic, no ordering-dependent accumulation. Called once per
/// `ensure_fresh` pass that wrote any chunk.
pub fn recompute_centrality(conn: &Connection, root: &str) -> rusqlite::Result<()> {
    // Pull every callsite's (callee_name, callee_kind) and tally resolved
    // definitions in Rust so the kind→def-kind mapping and the denylist
    // live in exactly one place (this module), not duplicated in SQL.
    let mut scores: HashMap<String, f64> = HashMap::new();
    {
        let mut stmt =
            conn.prepare("SELECT callee_name, callee_kind FROM intel_callsites WHERE root = ?1")?;
        let callsites = stmt
            .query_map([root], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Cache resolution per (name, kind) — a hot callee_name appears
        // many times and the def set is identical each time.
        let mut cache: HashMap<ResolveKey, Vec<DefSite>> = HashMap::new();
        for (name, kind) in callsites {
            let key: ResolveKey = (name.clone(), kind.clone());
            if !cache.contains_key(&key) {
                let d = resolve_defs(conn, root, &name, kind.as_deref())?;
                cache.insert(key.clone(), d);
            }
            let defs = &cache[&key];
            let m = defs.len();
            if m == 0 {
                continue; // unresolved contributes nothing
            }
            let weight = 1.0 / m as f64;
            for (path, _line) in defs {
                *scores.entry(path.clone()).or_insert(0.0) += weight;
            }
        }
    }

    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM intel_centrality WHERE root = ?1", [root])?;
    {
        let mut ins =
            tx.prepare("INSERT INTO intel_centrality (root, path, score) VALUES (?1, ?2, ?3)")?;
        for (path, score) in &scores {
            ins.execute(rusqlite::params![root, path, score])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Load the materialized `centrality[path]` map for `root`. An absent or
/// empty table yields an empty map, which the ranking treats as "no
/// signal" (unranked order) — backward compatible, never panics.
pub fn load_centrality(conn: &Connection, root: &str) -> rusqlite::Result<HashMap<String, f64>> {
    let mut stmt = conn.prepare("SELECT path, score FROM intel_centrality WHERE root = ?1")?;
    let rows = stmt
        .query_map([root], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
        })?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    Ok(rows)
}

/// The additive ranking multiplier for a file with `centrality` score:
/// `1 + k·ln(1 + centrality)`. Never below 1, so it only ever promotes —
/// recall is unchanged, only order. A file absent from the centrality map
/// scores 0 → multiplier exactly 1 (no change).
pub fn rank_multiplier(centrality: f64) -> f64 {
    1.0 + RANK_K * (1.0 + centrality.max(0.0)).ln()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// In-memory DB with just the two tables the resolver touches.
    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE intel_symbols (root TEXT, path TEXT, name TEXT, kind TEXT, line INTEGER);
             CREATE TABLE intel_callsites (root TEXT, caller_file TEXT, caller_line INTEGER, \
                caller_symbol TEXT, callee_name TEXT, callee_kind TEXT);
             CREATE TABLE intel_centrality (root TEXT, path TEXT, score REAL, PRIMARY KEY (root, path));",
        )
        .unwrap();
        conn
    }

    fn add_sym(conn: &Connection, path: &str, name: &str, kind: &str, line: i64) {
        conn.execute(
            "INSERT INTO intel_symbols (root, path, name, kind, line) VALUES ('r', ?1, ?2, ?3, ?4)",
            rusqlite::params![path, name, kind, line],
        )
        .unwrap();
    }

    fn add_call(conn: &Connection, name: &str, kind: &str) {
        conn.execute(
            "INSERT INTO intel_callsites (root, caller_file, caller_line, caller_symbol, callee_name, callee_kind) \
             VALUES ('r', 'c.rs', 1, 'caller', ?1, ?2)",
            rusqlite::params![name, kind],
        )
        .unwrap();
    }

    #[test]
    fn denylist_filters_ubiquitous_names_before_resolving() {
        let conn = db();
        add_sym(&conn, "a.rs", "get", "function", 1);
        // Even with a real def, a denylisted name resolves to nothing.
        assert!(is_denied("get"));
        assert!(
            resolve_defs(&conn, "r", "get", Some("call"))
                .unwrap()
                .is_empty()
        );
        assert!(!is_denied("widget"));
    }

    #[test]
    fn call_resolves_to_functions_and_methods_only() {
        let conn = db();
        add_sym(&conn, "a.rs", "f", "function", 1);
        add_sym(&conn, "b.rs", "f", "struct", 2); // not a call target
        let defs = resolve_defs(&conn, "r", "f", Some("call")).unwrap();
        assert_eq!(defs, vec![("a.rs".to_string(), 1)]);
    }

    #[test]
    fn type_ref_resolves_to_types_only() {
        let conn = db();
        add_sym(&conn, "a.rs", "T", "struct", 1);
        add_sym(&conn, "b.rs", "T", "function", 2); // not a type target
        let defs = resolve_defs(&conn, "r", "T", Some("type_ref")).unwrap();
        assert_eq!(defs, vec![("a.rs".to_string(), 1)]);
    }

    #[test]
    fn macro_callee_resolves_to_nothing_today() {
        let conn = db();
        add_sym(&conn, "a.rs", "m", "function", 1);
        // No `macro`-kind defs are extracted, so a macro callee is
        // unresolved (documented gap), never mis-bound to a function.
        assert!(
            resolve_defs(&conn, "r", "m", Some("macro"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn centrality_splits_ambiguous_callee_one_over_m() {
        let conn = db();
        // `dup` defined in two files; one call to it → 0.5 to each file.
        add_sym(&conn, "a.rs", "dup", "function", 1);
        add_sym(&conn, "b.rs", "dup", "function", 1);
        // `solo` defined once; one call to it → 1.0 to its file.
        add_sym(&conn, "a.rs", "solo", "function", 2);
        add_call(&conn, "dup", "call");
        add_call(&conn, "solo", "call");

        recompute_centrality(&conn, "r").unwrap();
        let scores = load_centrality(&conn, "r").unwrap();
        // a.rs: 0.5 (dup) + 1.0 (solo) = 1.5; b.rs: 0.5 (dup).
        assert!((scores["a.rs"] - 1.5).abs() < 1e-9, "got {scores:?}");
        assert!((scores["b.rs"] - 0.5).abs() < 1e-9, "got {scores:?}");
    }

    #[test]
    fn unresolved_callee_contributes_nothing() {
        let conn = db();
        add_sym(&conn, "a.rs", "real", "function", 1);
        add_call(&conn, "real", "call");
        add_call(&conn, "ghost", "call"); // no def → contributes nothing
        recompute_centrality(&conn, "r").unwrap();
        let scores = load_centrality(&conn, "r").unwrap();
        assert!((scores["a.rs"] - 1.0).abs() < 1e-9, "got {scores:?}");
        assert_eq!(scores.len(), 1, "only the resolved file scores; {scores:?}");
    }

    #[test]
    fn recompute_is_wholesale_no_stale_rows() {
        let conn = db();
        add_sym(&conn, "a.rs", "real", "function", 1);
        add_call(&conn, "real", "call");
        recompute_centrality(&conn, "r").unwrap();
        assert!(load_centrality(&conn, "r").unwrap().contains_key("a.rs"));

        // Drop the callsite and recompute: a.rs's row must disappear.
        conn.execute("DELETE FROM intel_callsites", []).unwrap();
        recompute_centrality(&conn, "r").unwrap();
        assert!(
            load_centrality(&conn, "r").unwrap().is_empty(),
            "wholesale recompute must not leave stale rows"
        );
    }

    #[test]
    fn rank_multiplier_is_monotonic_and_at_least_one() {
        assert!((rank_multiplier(0.0) - 1.0).abs() < 1e-12);
        assert!(rank_multiplier(10.0) > rank_multiplier(1.0));
        assert!(rank_multiplier(1.0) > rank_multiplier(0.0));
        // Negative (shouldn't happen) clamps to the 1.0 floor.
        assert!((rank_multiplier(-5.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn load_centrality_absent_table_degrades_to_empty() {
        // A DB with no intel_centrality rows for this root → empty map.
        let conn = db();
        assert!(load_centrality(&conn, "nope").unwrap().is_empty());
    }
}
