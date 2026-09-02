pub(super) use std::collections::{HashMap, HashSet};
pub(super) use std::path::{Path, PathBuf};

pub(super) use anyhow::Result;
pub(super) use async_trait::async_trait;
pub(super) use ignore::WalkBuilder;
pub(super) use serde::Deserialize;
pub(super) use serde_json::Value;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

pub(super) use crate::engine::tool::{
    Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input, typed_args,
};
pub(super) use crate::engine::{ToolProgress, TurnEvent};
pub(super) use crate::intel::budget::{BudgetedWriter, capture_text_artifact_body};
pub(super) use crate::intel::lang::{Language, regex_outline};
pub(super) use crate::intel::thin::{ThinLimits, thin_line_output};
pub(super) use crate::intel::{
    DepEdge, FileMetaRow, FreshenOptions, FreshenReport, Index, SymbolRow,
};

/// Token cap shared by the index tools. `search` uses a larger default
/// per the spec (4000); structural tools are terser so a tighter cap
/// keeps them well within the §10 economy.
pub(super) const SEARCH_TOKEN_CAP: usize = 4000;
pub(super) const STRUCT_TOKEN_CAP: usize = 3000;

#[cfg(test)]
type TestIndexAllowlistCell = Mutex<Option<(String, Vec<String>)>>;

#[cfg(test)]
static TEST_INDEX_ALLOWLIST: OnceLock<TestIndexAllowlistCell> = OnceLock::new();

#[cfg(test)]
pub(crate) fn set_test_index_allowlist(root: Option<String>, allow: Option<Vec<String>>) {
    *TEST_INDEX_ALLOWLIST
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = root.zip(allow);
}

#[cfg(test)]
fn test_index_allowlist(root: &Path) -> Option<Vec<String>> {
    TEST_INDEX_ALLOWLIST
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|(expected, allow)| {
            (root.to_string_lossy().as_ref() == expected).then(|| allow.clone())
        })
}

/// Filesystem root intel tools may read. A live workspace lease is a hard
/// visibility boundary: sibling worktrees and the primary repository are not
/// implicit index/walk roots.
pub(super) fn intel_root(ctx: &ToolCtx) -> &Path {
    ctx.workspace_lease
        .as_deref()
        .map(|lease| lease.visibility_root.as_path())
        .unwrap_or(ctx.session.project_root.as_path())
}

pub(super) fn index_of(ctx: &ToolCtx) -> Index {
    let root = intel_root(ctx);
    #[cfg(test)]
    let mut allow = test_index_allowlist(root)
        .unwrap_or_else(|| crate::config::extended::resolve_gitignore_allow(&ctx.cwd));
    #[cfg(not(test))]
    let mut allow = crate::config::extended::resolve_gitignore_allow(&ctx.cwd);
    allow.extend(ctx.session.gitignore_session_allow());
    Index::with_allowlist(ctx.session.db.clone(), root.to_path_buf(), allow)
        .with_exclude_dirs(crate::config::extended::resolve_intel_exclude_dirs(
            &ctx.cwd,
        ))
        .with_max_cold_index_files(crate::config::extended::resolve_intel_max_cold_index_files(
            &ctx.cwd,
        ))
}

/// Normalize a path arg to a relative forward-slash path against the
/// intel root — the form stored in the index.
pub(super) fn rel_path(arg: &str, ctx: &ToolCtx) -> String {
    let root = intel_root(ctx);
    let abs = crate::tools::common::resolve(arg, &ctx.cwd);
    match abs.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => arg.trim_start_matches("./").replace('\\', "/"),
    }
}

pub(super) fn finish(writer: BudgetedWriter, note: &str) -> ToolOutput {
    if writer.is_truncated() {
        let capture = writer.text_artifact_capture();
        let mut out = writer.into_string();
        out.push_str(note);
        match capture {
            Some(capture) => ToolOutput::truncated_text(out).with_text_artifact_capture(capture),
            None => ToolOutput::truncated_text(out),
        }
    } else {
        ToolOutput::text(writer.into_string())
    }
}

pub(super) fn append_freshen_note(out: &mut ToolOutput, report: &FreshenReport) {
    if let Some(note) = report.truncation_note() {
        if !out.content.ends_with('\n') {
            out.content.push('\n');
        }
        out.content.push_str(&note);
        out.content.push('\n');
    }
    if let Some(note) = report.secret_path_note() {
        if !out.content.ends_with('\n') {
            out.content.push('\n');
        }
        out.content.push_str(&note);
        out.content.push('\n');
    }
}

pub(super) fn freshen_options(ctx: &ToolCtx, scope: Option<String>) -> FreshenOptions {
    let mut options = FreshenOptions::default()
        .with_scope(scope)
        .with_cancel(ctx.cancel.clone());
    if let (Some(events), Some(call_id)) = (ctx.events.clone(), ctx.current_tool_call_id.clone()) {
        options = options.with_observer(move |progress| {
            let _ = events.try_send(TurnEvent::ToolProgress(ToolProgress {
                call_id: call_id.clone(),
                done: progress.done as u64,
                total: progress.total as u64,
                unit: "files".to_string(),
            }));
        });
    }
    options
}

pub(super) fn parent_scope_for_file(rel: &str, ctx: &ToolCtx) -> String {
    let abs = intel_root(ctx).join(rel);
    if abs.is_file()
        && let Some(parent) = Path::new(rel).parent()
    {
        let parent = parent.to_string_lossy().replace('\\', "/");
        if !parent.is_empty() {
            return parent;
        }
    }
    rel.to_string()
}

pub(super) fn write_retained_line(writer: &mut BudgetedWriter, line: &str) -> bool {
    writer.writeln(line);
    // Keep legacy `if !write...` call sites compiling while ensuring producers
    // continue far enough for `original_byte_len` to describe the whole output.
    true
}

pub(super) fn format_symbol_line(s: &SymbolRow) -> String {
    let span = if s.end_line > s.line {
        format!("{}-{}", s.line, s.end_line)
    } else {
        s.line.to_string()
    };
    let parent = s
        .parent
        .as_deref()
        .map(|p| format!("{p}."))
        .unwrap_or_default();
    let sig = s
        .signature
        .as_deref()
        .filter(|sig| !sig.trim().is_empty())
        .map(str::trim)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} {parent}{}", s.kind, s.name));
    format!("{}:{} {}", s.path, span, sig)
}

/// Reorder symbol hits by descending centrality (additive ranking,
/// Surface 1). A stable sort keyed on the rank multiplier preserves the
/// incoming `(path, line)` order as the tie-break, so the SET of hits is
/// untouched — only order changes. A path absent from `scores` ranks as
/// multiplier 1 (no change).
pub(super) fn rank_symbol_hits(
    hits: &mut [crate::intel::SymbolRow],
    scores: &HashMap<String, f64>,
) {
    hits.sort_by(|a, b| {
        let ma =
            crate::intel::callgraph::rank_multiplier(scores.get(&a.path).copied().unwrap_or(0.0));
        let mb =
            crate::intel::callgraph::rank_multiplier(scores.get(&b.path).copied().unwrap_or(0.0));
        // Descending by multiplier; NaN-safe (scores are finite).
        mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
    });
}

pub(super) fn intern(
    name: &str,
    nodes: &mut Vec<String>,
    idx: &mut HashMap<String, usize>,
    adj: &mut Vec<Vec<usize>>,
) -> usize {
    if let Some(&i) = idx.get(name) {
        return i;
    }
    let i = nodes.len();
    nodes.push(name.to_string());
    idx.insert(name.to_string(), i);
    adj.push(Vec::new());
    i
}

/// Iterative Tarjan strongly-connected-components over an adjacency
/// list. Returns one Vec of node indices per SCC. No `petgraph`.
pub(super) fn tarjan_scc(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adj.len();
    let mut index_counter = 0usize;
    let mut indices = vec![usize::MAX; n];
    let mut lowlink = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut result: Vec<Vec<usize>> = Vec::new();

    // Explicit work stack: (node, next-child-cursor).
    for start in 0..n {
        if indices[start] != usize::MAX {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&(v, ci)) = work.last() {
            if ci == 0 {
                indices[v] = index_counter;
                lowlink[v] = index_counter;
                index_counter += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if ci < adj[v].len() {
                let w = adj[v][ci];
                // Advance the cursor for v.
                work.last_mut().unwrap().1 += 1;
                if indices[w] == usize::MAX {
                    work.push((w, 0));
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(indices[w]);
                }
            } else {
                // Done with v's children: propagate lowlink to parent and
                // pop an SCC root.
                if lowlink[v] == indices[v] {
                    let mut comp = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    result.push(comp);
                }
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    lowlink[parent] = lowlink[parent].min(lowlink[v]);
                }
            }
        }
    }
    result
}

/// Shortest-distance BFS over an adjacency map, capped at `max_hops`.
/// Returns `(distance, node)` pairs (excludes the start node), sorted by
/// distance then path.
pub(super) fn bfs<'a>(
    adj: &HashMap<&'a str, Vec<&'a str>>,
    start: &str,
    max_hops: usize,
) -> Vec<(usize, String)> {
    let mut dist: HashMap<&str, usize> = HashMap::new();
    let mut queue: std::collections::VecDeque<&str> = std::collections::VecDeque::new();
    // Seed from the start node's own key (must match a &str inside adj).
    let start_key = adj.keys().find(|k| **k == start).copied();
    if let Some(sk) = start_key {
        dist.insert(sk, 0);
        queue.push_back(sk);
    } else {
        // Start has no outgoing edges in this map; still allow reverse
        // lookups by treating `start` as present with distance 0.
        return Vec::new();
    }
    while let Some(node) = queue.pop_front() {
        let d = dist[node];
        if d >= max_hops {
            continue;
        }
        if let Some(neighbors) = adj.get(node) {
            for &n in neighbors {
                if !dist.contains_key(n) {
                    dist.insert(n, d + 1);
                    queue.push_back(n);
                }
            }
        }
    }
    let mut out: Vec<(usize, String)> = dist
        .into_iter()
        .filter(|(_, d)| *d > 0)
        .map(|(p, d)| (d, p.to_string()))
        .collect();
    out.sort();
    out
}

pub(super) fn reverse_deps(
    edges: &[DepEdge],
    path: &str,
    depth: usize,
    filter: Option<&str>,
) -> Vec<(usize, String)> {
    let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        if let Some(importee) = &edge.importee {
            reverse.entry(importee).or_default().push(&edge.importer);
        }
    }
    bfs(&reverse, path, depth)
        .into_iter()
        .filter(|(_, p)| filter.is_none_or(|f| path_matches_filter(p, f)))
        .collect()
}

pub(super) fn forward_deps(
    edges: &[DepEdge],
    path: &str,
    depth: usize,
    filter: Option<&str>,
) -> Vec<(usize, String)> {
    let mut forward: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        if let Some(importee) = &edge.importee {
            forward.entry(&edge.importer).or_default().push(importee);
        }
    }
    bfs(&forward, path, depth)
        .into_iter()
        .filter(|(_, p)| filter.is_none_or(|f| path_matches_filter(p, f)))
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct FsFileMeta {
    pub rel: String,
    pub size: u64,
    pub mtime: Option<std::time::SystemTime>,
}

/// Gitignore-aware list of file metadata for every tracked file.
pub(crate) fn list_file_metas(
    root: &Path,
    exclude_dirs: &[String],
    scope: Option<&str>,
) -> Vec<FsFileMeta> {
    let mut out = Vec::new();
    if scope.is_some_and(crate::intel::invalid_intel_scope) {
        return out;
    }
    let walk_root = scope.map_or_else(|| root.to_path_buf(), |scope| root.join(scope));
    let walker = crate::intel::intel_walk_builder(
        root,
        &walk_root,
        exclude_dirs,
        crate::intel::IntelWalkMode {
            gitignore: true,
            hidden: true,
            explicit_scope: scope.is_some(),
        },
    );
    for dent in walker.build().flatten() {
        if !dent.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let abs = dent.path().to_path_buf();
        let Ok(rel) = abs.strip_prefix(root) else {
            continue;
        };
        let meta = dent.metadata().ok();
        out.push(FsFileMeta {
            rel: rel.to_string_lossy().replace('\\', "/"),
            size: meta.as_ref().map_or(0, std::fs::Metadata::len),
            mtime: meta.and_then(|m| m.modified().ok()),
        });
    }
    out
}

pub(super) fn count_lines(abs: &Path) -> usize {
    match crate::resource_limits::read_for_tool(abs) {
        Ok(b) if !b.contains(&0u8) => bytecount(&b),
        _ => 0,
    }
}

pub(super) fn path_matches_filter(path: &str, filter: &str) -> bool {
    path == filter || path.starts_with(&format!("{filter}/"))
}

pub(super) fn bytecount(b: &[u8]) -> usize {
    if b.is_empty() {
        return 0;
    }
    let nl = b.iter().filter(|&&c| c == b'\n').count();
    // Count a trailing partial line.
    if b.last() == Some(&b'\n') { nl } else { nl + 1 }
}
