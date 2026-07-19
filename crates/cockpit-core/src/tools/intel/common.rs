pub(super) use std::collections::{HashMap, HashSet};
pub(super) use std::path::{Path, PathBuf};

pub(super) use anyhow::Result;
pub(super) use async_trait::async_trait;
pub(super) use ignore::WalkBuilder;
pub(super) use serde::Deserialize;
pub(super) use serde_json::Value;

pub(super) use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
pub(super) use crate::intel::budget::{BudgetedWriter, retained_truncated_body};
pub(super) use crate::intel::lang::{Language, regex_outline};
pub(super) use crate::intel::thin::{ThinLimits, thin_line_output};
pub(super) use crate::intel::{DepEdge, FileMetaRow, Index, SymbolRow};

/// Token cap shared by the index tools. `search` uses a larger default
/// per the spec (4000); structural tools are terser so a tighter cap
/// keeps them well within the §10 economy.
pub(super) const SEARCH_TOKEN_CAP: usize = 4000;
pub(super) const STRUCT_TOKEN_CAP: usize = 3000;

pub(super) fn index_of(ctx: &ToolCtx) -> Index {
    let mut allow = crate::config::extended::resolve_gitignore_allow(&ctx.cwd);
    allow.extend(ctx.session.gitignore_session_allow());
    Index::with_allowlist(
        ctx.session.db.clone(),
        ctx.session.project_root.clone(),
        allow,
    )
}

/// Normalize a path arg to a relative forward-slash path against the
/// project root — the form stored in the index.
pub(super) fn rel_path(arg: &str, ctx: &ToolCtx) -> String {
    let root = &ctx.session.project_root;
    let abs = crate::tools::common::resolve(arg, &ctx.cwd);
    match abs.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => arg.trim_start_matches("./").replace('\\', "/"),
    }
}

pub(super) fn finish(writer: BudgetedWriter, note: &str) -> ToolOutput {
    if writer.is_truncated() {
        let retention = writer.retained_truncated_output();
        let mut out = writer.into_string();
        out.push_str(note);
        match retention {
            Some(retention) => ToolOutput::truncated_text(out).with_truncated_retention(retention),
            None => ToolOutput::truncated_text(out),
        }
    } else {
        ToolOutput::text(writer.into_string())
    }
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
pub(super) struct FsFileMeta {
    pub rel: String,
    pub abs: PathBuf,
    pub size: u64,
    pub mtime: Option<std::time::SystemTime>,
}

/// Gitignore-aware list of `(rel, abs, size)` for every tracked file.
pub(super) fn list_files(root: &Path) -> Vec<(String, PathBuf, u64)> {
    list_file_metas_from(root, root)
        .into_iter()
        .map(|file| (file.rel, file.abs, file.size))
        .collect()
}

/// Gitignore-aware list of file metadata for every tracked file.
pub(super) fn list_file_metas(root: &Path) -> Vec<FsFileMeta> {
    list_file_metas_from(root, root)
}

/// Gitignore-aware list rooted at `root/subdir`, with paths relative to `root`.
pub(super) fn list_files_under(root: &Path, subdir: &str) -> Vec<(String, PathBuf, u64)> {
    list_file_metas_from(root, &root.join(subdir))
        .into_iter()
        .map(|file| (file.rel, file.abs, file.size))
        .collect()
}

fn list_file_metas_from(root: &Path, walk_root: &Path) -> Vec<FsFileMeta> {
    let mut out = Vec::new();
    let mut walker = WalkBuilder::new(walk_root);
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
        let abs = dent.path().to_path_buf();
        let Ok(rel) = abs.strip_prefix(root) else {
            continue;
        };
        let meta = dent.metadata().ok();
        out.push(FsFileMeta {
            rel: rel.to_string_lossy().replace('\\', "/"),
            abs,
            size: meta.as_ref().map_or(0, std::fs::Metadata::len),
            mtime: meta.and_then(|m| m.modified().ok()),
        });
    }
    out
}

pub(super) fn count_lines(abs: &Path) -> usize {
    match std::fs::read(abs) {
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
