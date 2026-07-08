//! Codebase-intelligence tools (GOALS §21, Phase 1).
//!
//! Eleven tools backed by the on-demand [`crate::intel::Index`]: `tree`,
//! `outline`, `symbol_find`, `word`, `deps`, `hot`, `circular`,
//! `search`, `impact`, `change_impact`, and `context_pack`. Each index-backed tool calls
//! [`Index::ensure_fresh`] first so it never answers from stale data.
//! `hot` is pure-FS (no index). `search` and `symbol_find` additionally
//! apply call-graph centrality ranking (additive, default-on,
//! config-gated via `extended.intelCentralityRanking`); `impact` reports
//! a symbol's high-precision-resolved callers and calls.
//! `search` shells `rg --json` (falling back to `grep -rn`) and
//! budget-caps its output via [`crate::intel::budget::BudgetedWriter`].
//! The `rg --json`/`grep -rn` path emits `path:line:text`; the `grep`
//! fallback's context case (`-C{n}`) is a known limitation — its context
//! lines use a `path-line-text` (dash) separator that isn't carried
//! through cleanly.
//!
//! Output never self-scrubs: `engine::agent::turn` runs every tool
//! result through `redact::scrub` before it reaches the model.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use ignore::WalkBuilder;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::intel::budget::BudgetedWriter;
use crate::intel::lang::{Language, regex_outline};
use crate::intel::thin::{ThinLimits, thin_line_output};
use crate::intel::{DepEdge, Index, SymbolRow};

/// Token cap shared by the index tools. `search` uses a larger default
/// per the spec (4000); structural tools are terser so a tighter cap
/// keeps them well within the §10 economy.
const SEARCH_TOKEN_CAP: usize = 4000;
const STRUCT_TOKEN_CAP: usize = 3000;

/// Build an index handle from the tool ctx (project-root scoped). The
/// effective gitignore read-allowlist (persisted per-layer config ∪ the
/// session set) is threaded in so allowlisted-but-gitignored files surface in
/// the intel tools (implementation note).
fn index_of(ctx: &ToolCtx) -> Index {
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
fn rel_path(arg: &str, ctx: &ToolCtx) -> String {
    let root = &ctx.session.project_root;
    let abs = crate::tools::common::resolve(arg, &ctx.cwd);
    match abs.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => arg.trim_start_matches("./").replace('\\', "/"),
    }
}

/// `tree` treats a narrow set of root-like spellings as "no filter" so
/// weak models asking for the repo root don't fall into an empty-path
/// loop. Non-root spellings keep the normal subtree semantics.
fn tree_filter_path(args: &Value, ctx: &ToolCtx) -> (Option<String>, Option<Value>) {
    let Some(path) = args.get("path").and_then(Value::as_str) else {
        return (None, None);
    };

    let filter = match path.trim() {
        "" | "." | "./" | "/" => None,
        _ if Path::new(path).is_absolute()
            && crate::tools::common::resolve(path, &ctx.cwd) == ctx.session.project_root =>
        {
            None
        }
        _ => Some(rel_path(path, ctx)),
    };

    let canonical_args = match &filter {
        None => Some(serde_json::json!({})),
        Some(rel) if path != rel => Some(serde_json::json!({ "path": rel })),
        Some(_) => None,
    };

    (filter, canonical_args)
}

fn tree_repeat_guard_message() -> &'static str {
    "Previous `tree` call with the same `path` already returned no matches. Do not repeat it. Run `tree` without `path` to list the repo root, or choose a different subtree."
}

fn finish(writer: BudgetedWriter, note: &str) -> ToolOutput {
    if writer.is_truncated() {
        let mut out = writer.into_string();
        out.push_str(note);
        ToolOutput::truncated_text(out)
    } else {
        ToolOutput::text(writer.into_string())
    }
}

// ---- context_pack ----------------------------------------------------------

pub struct ContextPackTool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextPackKind {
    Auto,
    Overview,
    Path,
    Symbol,
    Query,
}

#[derive(Debug, Clone)]
struct ContextFileMeta {
    path: String,
    language: String,
    size: u64,
    lines: usize,
    symbols: i64,
    mtime: Option<std::time::SystemTime>,
    centrality: f64,
    centrality_rank: Option<usize>,
}

#[async_trait]
impl Tool for ContextPackTool {
    fn name(&self) -> &str {
        "context_pack"
    }

    fn description(&self) -> &str {
        "Return a dense read-only codebase context packet for an overview, file, symbol, or query"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Fast first move for broad orientation: combine indexed files, symbols, imports, dependencies, centrality, recency, and call context into one compact read-only packet. It never prints file contents; use `read` after it for narrow ranges."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "target": { "type": "string", "description": "Optional path, symbol name, or search text to focus the packet" },
                "kind": { "type": "string", "description": "auto, overview, path, symbol, or query. Defaults to auto" },
                "depth": { "type": "integer", "description": "Relationship depth for dependency/call context, 1-3. Defaults to 1" },
                "limit": { "type": "integer", "description": "Maximum primary items per section, 1-50. Defaults to 12" }
            }
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let target = args
            .get("target")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let requested = parse_context_pack_kind(args.get("kind").and_then(Value::as_str))?;
        let depth = args
            .get("depth")
            .and_then(Value::as_u64)
            .map(|d| d.clamp(1, 3) as usize)
            .unwrap_or(1);
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| l.clamp(1, 50) as usize)
            .unwrap_or(12);

        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let tree_rows = index.tree_rows()?;
        let fs_files = list_files(&ctx.session.project_root);
        if tree_rows.is_empty() && fs_files.is_empty() {
            return Ok(ToolOutput::text(format!(
                "context_pack: no indexed files\nproject_root: {}\ncwd: {}\nhint: verify the project root/cwd; try `context_pack` again after files exist, or use `tree`/`rg --files` to diagnose discovery.",
                ctx.session.project_root.display(),
                ctx.cwd.display()
            )));
        }

        let centrality = index.centrality_scores()?;
        let files = context_file_meta(&tree_rows, &fs_files, &centrality);
        let kind = match requested {
            ContextPackKind::Auto => match target {
                None => ContextPackKind::Overview,
                Some(t) if resolve_context_path(t, ctx, &files).is_some() => ContextPackKind::Path,
                Some(t) if !index.symbol_find(t, false, None)?.is_empty() => {
                    ContextPackKind::Symbol
                }
                Some(_) => ContextPackKind::Query,
            },
            other => other,
        };

        match kind {
            ContextPackKind::Auto => unreachable!("auto is resolved above"),
            ContextPackKind::Overview => context_pack_overview(&index, &files, depth, limit),
            ContextPackKind::Path => {
                let Some(target) = target else {
                    return Err(invalid_input("`target` is required for kind=path"));
                };
                let Some(rel) = resolve_context_path(target, ctx, &files) else {
                    return Err(invalid_input(format!(
                        "path target `{target}` was not found; try `context_pack` without `target` or run `tree`"
                    )));
                };
                context_pack_path(&index, &files, &rel, depth, limit)
            }
            ContextPackKind::Symbol => {
                let Some(target) = target else {
                    return Err(invalid_input("`target` is required for kind=symbol"));
                };
                context_pack_symbol(&index, &files, target, depth, limit)
            }
            ContextPackKind::Query => {
                let Some(target) = target else {
                    return Err(invalid_input("`target` is required for kind=query"));
                };
                context_pack_query(&index, &files, target, ctx, limit)
            }
        }
    }
}

fn parse_context_pack_kind(raw: Option<&str>) -> Result<ContextPackKind> {
    match raw.unwrap_or("auto").trim() {
        "" | "auto" => Ok(ContextPackKind::Auto),
        "overview" => Ok(ContextPackKind::Overview),
        "path" => Ok(ContextPackKind::Path),
        "symbol" => Ok(ContextPackKind::Symbol),
        "query" => Ok(ContextPackKind::Query),
        other => Err(invalid_input(format!(
            "invalid `kind` `{other}`; expected overview, path, symbol, query, or auto"
        ))),
    }
}

fn context_file_meta(
    tree_rows: &[(String, String, i64, i64)],
    fs_files: &[(String, PathBuf, u64)],
    centrality: &HashMap<String, f64>,
) -> Vec<ContextFileMeta> {
    let indexed: HashMap<&str, (&str, i64, i64)> = tree_rows
        .iter()
        .map(|(p, lang, size, syms)| (p.as_str(), (lang.as_str(), *size, *syms)))
        .collect();
    let mut ranked: Vec<(&String, &f64)> = centrality.iter().collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });
    let ranks: HashMap<&str, usize> = ranked
        .iter()
        .enumerate()
        .map(|(idx, (path, _))| (path.as_str(), idx + 1))
        .collect();

    let mut metas = Vec::new();
    let mut seen = HashSet::new();
    for (rel, abs, fs_size) in fs_files {
        seen.insert(rel.clone());
        let (language, size, symbols) = indexed
            .get(rel.as_str())
            .map(|(l, s, syms)| ((*l).to_string(), (*s).max(0) as u64, *syms))
            .unwrap_or_else(|| {
                (
                    Language::from_path(Path::new(rel)).as_str().to_string(),
                    *fs_size,
                    0,
                )
            });
        let meta = std::fs::metadata(abs).ok();
        metas.push(ContextFileMeta {
            path: rel.clone(),
            language,
            size,
            lines: count_lines(abs),
            symbols,
            mtime: meta.and_then(|m| m.modified().ok()),
            centrality: centrality.get(rel).copied().unwrap_or(0.0),
            centrality_rank: ranks.get(rel.as_str()).copied(),
        });
    }
    for (path, language, size, symbols) in tree_rows {
        if seen.contains(path) {
            continue;
        }
        metas.push(ContextFileMeta {
            path: path.clone(),
            language: language.clone(),
            size: (*size).max(0) as u64,
            lines: 0,
            symbols: *symbols,
            mtime: None,
            centrality: centrality.get(path).copied().unwrap_or(0.0),
            centrality_rank: ranks.get(path.as_str()).copied(),
        });
    }
    metas.sort_by(|a, b| a.path.cmp(&b.path));
    metas
}

fn resolve_context_path(target: &str, ctx: &ToolCtx, files: &[ContextFileMeta]) -> Option<String> {
    let rel = rel_path(target, ctx);
    if files.iter().any(|f| f.path == rel) {
        return Some(rel);
    }
    let abs = crate::tools::common::resolve(target, &ctx.cwd);
    if abs.is_file()
        && let Ok(rel) = abs.strip_prefix(&ctx.session.project_root)
    {
        let rel = rel.to_string_lossy().replace('\\', "/");
        if files.iter().any(|f| f.path == rel) {
            return Some(rel);
        }
    }
    None
}

fn context_pack_overview(
    index: &Index,
    files: &[ContextFileMeta],
    depth: usize,
    limit: usize,
) -> Result<ToolOutput> {
    let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
    let indexed = files.iter().filter(|f| f.symbols > 0).count();
    writer.writeln("context_pack: overview");
    writer.writeln(&format!(
        "files: {} discovered, {} with symbols",
        files.len(),
        indexed
    ));

    let mut langs: HashMap<&str, usize> = HashMap::new();
    for file in files {
        *langs.entry(file.language.as_str()).or_default() += 1;
    }
    let mut lang_rows: Vec<_> = langs.into_iter().collect();
    lang_rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    writer.writeln("languages:");
    for (lang, count) in lang_rows.into_iter().take(limit) {
        if !writer.writeln(&format!("  {lang}: {count}")) {
            return Ok(finish(
                writer,
                "\n... [truncated; lower `limit` or target a path]\n",
            ));
        }
    }

    writer.writeln("top central files:");
    let mut central = files
        .iter()
        .filter(|f| f.centrality > 0.0)
        .collect::<Vec<_>>();
    central.sort_by(|a, b| {
        b.centrality
            .partial_cmp(&a.centrality)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.path.cmp(&b.path))
    });
    if central.is_empty() {
        writer.writeln("  none");
    } else {
        for file in central.into_iter().take(limit) {
            if !writer.writeln(&format!(
                "  {} score={:.2} symbols={}",
                file.path, file.centrality, file.symbols
            )) {
                return Ok(finish(writer, "\n... [truncated; lower `limit`]\n"));
            }
        }
    }

    writer.writeln("recent files:");
    let mut recent = files
        .iter()
        .filter(|f| f.mtime.is_some())
        .collect::<Vec<_>>();
    recent.sort_by(|a, b| b.mtime.cmp(&a.mtime).then_with(|| a.path.cmp(&b.path)));
    for file in recent.into_iter().take(limit) {
        if !writer.writeln(&format!("  {}  {}b {}L", file.path, file.size, file.lines)) {
            return Ok(finish(writer, "\n... [truncated; lower `limit`]\n"));
        }
    }

    writer.writeln("largest symbol-bearing files:");
    let mut symbol_heavy = files.iter().filter(|f| f.symbols > 0).collect::<Vec<_>>();
    symbol_heavy.sort_by(|a, b| {
        b.symbols
            .cmp(&a.symbols)
            .then_with(|| b.size.cmp(&a.size))
            .then_with(|| a.path.cmp(&b.path))
    });
    if symbol_heavy.is_empty() {
        writer.writeln("  none");
    } else {
        for file in symbol_heavy.into_iter().take(limit) {
            if !writer.writeln(&format!(
                "  {} {} symbols={} {}L",
                file.path, file.language, file.symbols, file.lines
            )) {
                return Ok(finish(writer, "\n... [truncated; lower `limit`]\n"));
            }
        }
    }

    writer.writeln("entry candidates:");
    let entries = entry_candidates(index, limit)?;
    if entries.is_empty() {
        writer.writeln("  none detected");
    } else {
        for s in entries {
            if !writer.writeln(&format_symbol_line(&s)) {
                return Ok(finish(writer, "\n... [truncated; target a symbol]\n"));
            }
        }
    }

    let cycles = import_cycles(index.dep_edges()?);
    writer.writeln(&format!("import cycles: {}", cycles.len()));
    for cycle in cycles.into_iter().take(limit.min(5)) {
        if !writer.writeln(&format!("  {}", cycle.join(" -> "))) {
            return Ok(finish(writer, "\n... [truncated; use `circular`]\n"));
        }
    }
    writer.writeln(&format!("next: context_pack {{target:<path|symbol>, depth:{depth}}}; outline <path>; deps <path>; symbol_find <name>"));
    Ok(finish(
        writer,
        "\n... [truncated; target a path, symbol, or query]\n",
    ))
}

fn context_pack_path(
    index: &Index,
    files: &[ContextFileMeta],
    rel: &str,
    depth: usize,
    limit: usize,
) -> Result<ToolOutput> {
    let Some(file) = files.iter().find(|f| f.path == rel) else {
        return Ok(ToolOutput::text(format!(
            "context_pack: path\npath: {rel}\nnot indexed"
        )));
    };
    let (symbols, imports, language) = index.outline_rows(rel)?;
    let edges = index.dep_edges()?;
    let reverse = reverse_deps(&edges, rel, depth, None);
    let forward = forward_deps(&edges, rel, depth, None);
    let unresolved: Vec<_> = edges
        .iter()
        .filter(|e| e.importer == rel && e.importee.is_none())
        .collect();

    let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
    writer.writeln("context_pack: path");
    writer.writeln(&format!("path: {rel}"));
    writer.writeln(&format!(
        "meta: lang={} size={}b lines={} symbols={}",
        if language.is_empty() {
            &file.language
        } else {
            &language
        },
        file.size,
        file.lines,
        symbols.len()
    ));
    if let Some(rank) = file.centrality_rank {
        writer.writeln(&format!(
            "centrality: rank #{rank} score {:.2}",
            file.centrality
        ));
    } else {
        writer.writeln("centrality: none");
    }
    if let Some(mtime) = file.mtime.and_then(system_time_secs) {
        writer.writeln(&format!("mtime_unix: {mtime}"));
    }

    writer.writeln("imports:");
    if imports.is_empty() {
        writer.writeln("  none");
    } else {
        for (target, line) in imports.iter().take(limit) {
            if !writer.writeln(&format!("  {rel}:{line} -> {target}")) {
                return Ok(finish(writer, "\n... [truncated; lower `limit`]\n"));
            }
        }
        write_omitted(&mut writer, imports.len(), limit, "imports");
    }

    writer.writeln("outline:");
    if symbols.is_empty() {
        writer.writeln("  none");
    } else {
        for s in symbols.iter().take(limit) {
            if !writer.writeln(&format!("  {}", format_symbol_line(s))) {
                return Ok(finish(writer, "\n... [truncated; use `outline`]\n"));
            }
        }
        write_omitted(&mut writer, symbols.len(), limit, "symbols");
    }

    writer.writeln(&format!("dependencies depth={depth}:"));
    writer.writeln("  forward:");
    if !write_dep_rows(&mut writer, &forward, limit) {
        return Ok(finish(
            writer,
            "
... [truncated; use `deps`]
",
        ));
    }
    writer.writeln("  reverse:");
    if !write_dep_rows(&mut writer, &reverse, limit) {
        return Ok(finish(
            writer,
            "
... [truncated; use `deps`]
",
        ));
    }
    if !unresolved.is_empty() {
        writer.writeln("  unresolved imports:");
        for edge in unresolved.iter().take(limit) {
            if !writer.writeln(&format!("    {}: {}", edge.line, edge.raw_target)) {
                return Ok(finish(writer, "\n... [truncated; use `deps`]\n"));
            }
        }
    }

    writer.writeln("suggested reads:");
    if symbols.is_empty() {
        writer.writeln(&format!("  read {{path:\"{rel}\", offset:1, limit:80}}"));
    } else {
        for s in symbols.iter().take(limit.min(4)) {
            let start = s.line.max(1);
            let len = (s.end_line - s.line + 1).clamp(20, 120);
            if !writer.writeln(&format!(
                "  read {{path:\"{}\", offset:{}, limit:{}}}  # {}",
                s.path, start, len, s.name
            )) {
                return Ok(finish(writer, "\n... [truncated]\n"));
            }
        }
    }
    writer.writeln(&format!(
        "next: outline {rel}; deps {rel} direction=reverse hops={depth}; read narrow ranges above"
    ));
    Ok(finish(
        writer,
        "\n... [truncated; use `outline` or `deps`]\n",
    ))
}

fn context_pack_symbol(
    index: &Index,
    files: &[ContextFileMeta],
    target: &str,
    _depth: usize,
    limit: usize,
) -> Result<ToolOutput> {
    let mut hits = index.symbol_find(target, true, None)?;
    if hits.is_empty() {
        hits = index.symbol_find(target, false, None)?;
    }
    if hits.is_empty() {
        return Ok(ToolOutput::text(format!(
            "context_pack: symbol\ntarget: {target}\nNo symbol matches `{target}`.\nnext: context_pack {{target:\"{target}\", kind:\"query\"}}; search pattern={target:?}"
        )));
    }
    let centrality: HashMap<String, f64> = files
        .iter()
        .map(|f| (f.path.clone(), f.centrality))
        .collect();
    rank_symbol_hits(&mut hits, &centrality);

    let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
    writer.writeln("context_pack: symbol");
    writer.writeln(&format!("target: {target}"));
    writer.writeln(&format!("definitions: {}", hits.len()));
    for s in hits.iter().take(limit) {
        let score = centrality.get(&s.path).copied().unwrap_or(0.0);
        if !writer.writeln(&format!(
            "  {} centrality={:.2}",
            format_symbol_line(s),
            score
        )) {
            return Ok(finish(
                writer,
                "\n... [truncated; narrow with exact target/path]\n",
            ));
        }
    }
    write_omitted(&mut writer, hits.len(), limit, "definitions");

    writer.writeln("call context:");
    let mut any = false;
    for s in hits.iter().take(limit.min(5)) {
        let callers = index.impact_callers(&s.path, s.line).unwrap_or_default();
        let calls = index.impact_calls(&s.name).unwrap_or_default();
        if callers.is_empty() && calls.is_empty() {
            continue;
        }
        any = true;
        writer.writeln(&format!("  {}:{} {}", s.path, s.line, s.name));
        for (caller_file, caller_line, caller_symbol) in callers.into_iter().take(limit) {
            let in_sym = caller_symbol
                .map(|v| format!(" in {v}"))
                .unwrap_or_default();
            if !writer.writeln(&format!("    caller {caller_file}:{caller_line}{in_sym}")) {
                return Ok(finish(writer, "\n... [truncated; use `impact`]\n"));
            }
        }
        for (callee, def_file, def_line) in calls.into_iter().take(limit) {
            if !writer.writeln(&format!("    calls {callee} -> {def_file}:{def_line}")) {
                return Ok(finish(writer, "\n... [truncated; use `impact`]\n"));
            }
        }
    }
    if !any {
        writer.writeln("  none");
    }

    writer.writeln("suggested reads:");
    for s in hits.iter().take(limit.min(6)) {
        let len = (s.end_line - s.line + 1).clamp(20, 120);
        if !writer.writeln(&format!(
            "  read {{path:\"{}\", offset:{}, limit:{}}}  # {}",
            s.path, s.line, len, s.name
        )) {
            return Ok(finish(writer, "\n... [truncated]\n"));
        }
    }
    writer.writeln(&format!(
        "next: impact name={target:?}; read suggested ranges; word token={target:?}"
    ));
    Ok(finish(
        writer,
        "\n... [truncated; narrow target or use `impact`]\n",
    ))
}

fn context_pack_query(
    index: &Index,
    files: &[ContextFileMeta],
    target: &str,
    ctx: &ToolCtx,
    limit: usize,
) -> Result<ToolOutput> {
    let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
    writer.writeln("context_pack: query");
    writer.writeln(&format!("target: {target}"));

    let mut symbol_hits = index.symbol_find(target, false, None)?;
    let centrality: HashMap<String, f64> = files
        .iter()
        .map(|f| (f.path.clone(), f.centrality))
        .collect();
    rank_symbol_hits(&mut symbol_hits, &centrality);
    writer.writeln("likely symbols:");
    if symbol_hits.is_empty() {
        writer.writeln("  none");
    } else {
        for s in symbol_hits.iter().take(limit) {
            if !writer.writeln(&format!("  {}", format_symbol_line(s))) {
                return Ok(finish(writer, "\n... [truncated; narrow query]\n"));
            }
        }
    }

    writer.writeln("identifier hits:");
    let token_hits = if is_identifierish(target) {
        index.word_hits(target, true)?
    } else {
        Vec::new()
    };
    if token_hits.is_empty() {
        writer.writeln("  none");
    } else {
        for (path, lines) in token_hits.iter().take(limit) {
            let joined = lines
                .iter()
                .take(8)
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            if !writer.writeln(&format!("  {path}: {joined}")) {
                return Ok(finish(writer, "\n... [truncated; use `word`]\n"));
            }
        }
    }

    writer.writeln("text hits (content omitted):");
    let text_hits = literal_text_hits(target, ctx, limit.saturating_mul(2))?;
    if text_hits.is_empty() {
        writer.writeln("  none");
    } else {
        for (path, line) in text_hits.into_iter().take(limit) {
            if !writer.writeln(&format!("  {path}:{line}")) {
                return Ok(finish(writer, "\n... [truncated; use `search`]\n"));
            }
        }
    }

    writer.writeln(&format!("next: search pattern={target:?}; symbol_find name={target:?}; word token={target:?}; read promising anchors"));
    Ok(finish(
        writer,
        "\n... [truncated; narrow query or use `search`]\n",
    ))
}

fn entry_candidates(index: &Index, limit: usize) -> Result<Vec<SymbolRow>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for name in ["main", "run", "start", "init", "cli"] {
        for sym in index.symbol_find(name, true, None)? {
            if seen.insert((sym.path.clone(), sym.line, sym.name.clone())) {
                out.push(sym);
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    out.truncate(limit);
    Ok(out)
}

fn import_cycles(edges: Vec<DepEdge>) -> Vec<Vec<String>> {
    let mut nodes: Vec<String> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    let mut adj: Vec<Vec<usize>> = Vec::new();
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    for edge in edges {
        if let Some(importee) = edge.importee {
            let a = intern(&edge.importer, &mut nodes, &mut idx, &mut adj);
            let b = intern(&importee, &mut nodes, &mut idx, &mut adj);
            if seen_edges.insert((a, b)) {
                adj[a].push(b);
            }
        }
    }
    let mut cycles = Vec::new();
    for comp in tarjan_scc(&adj) {
        let is_cycle = comp.len() > 1 || comp.first().is_some_and(|&n| adj[n].contains(&n));
        if !is_cycle {
            continue;
        }
        let mut names = comp
            .into_iter()
            .map(|i| nodes[i].clone())
            .collect::<Vec<_>>();
        names.sort();
        if let Some(first) = names.first().cloned() {
            names.push(first);
        }
        cycles.push(names);
    }
    cycles.sort();
    cycles
}

fn write_dep_rows(writer: &mut BudgetedWriter, rows: &[(usize, String)], limit: usize) -> bool {
    if rows.is_empty() {
        return writer.writeln("    none");
    }
    for (dist, path) in rows.iter().take(limit) {
        if !writer.writeln(&format!("    [{dist}] {path}")) {
            return false;
        }
    }
    write_omitted(writer, rows.len(), limit, "dependencies");
    true
}

fn write_omitted(writer: &mut BudgetedWriter, total: usize, limit: usize, label: &str) {
    if total > limit {
        let _ = writer.writeln(&format!("  ... [{} more {label} omitted]", total - limit));
    }
}

fn format_symbol_line(s: &SymbolRow) -> String {
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

fn system_time_secs(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn is_identifierish(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn literal_text_hits(target: &str, ctx: &ToolCtx, max_hits: usize) -> Result<Vec<(String, usize)>> {
    let escaped = regex::escape(target);
    let re = regex::Regex::new(&escaped).map_err(|e| invalid_input(e.to_string()))?;
    let mut out = Vec::new();
    for (rel, abs, _) in list_files(&ctx.session.project_root) {
        if out.len() >= max_hits {
            break;
        }
        let Ok(bytes) = std::fs::read(&abs) else {
            continue;
        };
        if bytes.contains(&0u8) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            if re.is_match(line) {
                out.push((rel.clone(), idx + 1));
                if out.len() >= max_hits {
                    break;
                }
            }
        }
    }
    Ok(out)
}

// ---- tree ------------------------------------------------------------------

pub struct TreeTool;

#[async_trait]
impl Tool for TreeTool {
    fn name(&self) -> &str {
        "tree"
    }
    fn description(&self) -> &str {
        "List indexed files with language, size, line count, and symbol count"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Map the codebase from cockpit's index: every file with language, size, lines, and \
             symbol count (scope with `path`). This is your FIRST move in any repo you don't \
             already know — call it before reading or searching anything. It lists discovered \
             files; if the result is empty, treat the diagnostic as a project-root/cwd or `path` \
             filter problem and recover with its hint. Use it instead of `ls`/`find` in `bash`. After it: \
             `read` a specific file, or `outline` it for its shape."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Subtree `path` filter relative to project root" }
            }
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Optional subtree to restrict the listing to, relative to the project root; omit to list the whole indexed tree" }
            }
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let (filter, canonical_args) = tree_filter_path(&args, ctx);

        // Indexed files (with symbol counts) keyed by path.
        let indexed: HashMap<String, (String, i64, i64)> = index
            .tree_rows()?
            .into_iter()
            .map(|(p, lang, size, syms)| (p, (lang, size, syms)))
            .collect();

        // The on-disk gitignore walk is the authority for which files
        // exist (it sees unknown-language files the index doesn't store).
        let mut entries = list_files(&ctx.session.project_root);
        entries.sort();

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for (rel, abs, size) in &entries {
            if let Some(f) = &filter
                && !(rel == f || rel.starts_with(&format!("{f}/")))
            {
                continue;
            }
            let lang = Language::from_path(Path::new(rel));
            let (lang_str, sym_part) = match indexed.get(rel) {
                Some((l, _s, syms)) => (l.clone(), format!("[{syms} sym]")),
                None => (lang.as_str().to_string(), "[not indexed]".to_string()),
            };
            let lines = count_lines(abs);
            let line = format!("{rel}  {lang_str} {size}b {lines}L {sym_part}");
            if !writer.writeln(&line) {
                break;
            }
        }
        if writer.is_empty() && !writer.is_truncated() {
            let mut out = ToolOutput::text(tree_empty_diagnostic(
                filter.as_deref(),
                entries.len(),
                indexed.len(),
                ctx,
            ));
            if filter.is_some() {
                out = out.with_repeat_guard(tree_repeat_guard_message());
            }
            if let Some(canonical) = canonical_args {
                out.canonical_args = Some(canonical);
            }
            return Ok(out);
        }
        let mut out = finish(
            writer,
            "\n... [truncated; pass `path` to scope to a subtree]\n",
        );
        if let Some(canonical) = canonical_args {
            out.canonical_args = Some(canonical);
        }
        Ok(out)
    }
}

fn tree_empty_diagnostic(
    filter: Option<&str>,
    fs_files: usize,
    indexed_files: usize,
    ctx: &ToolCtx,
) -> String {
    let mut out = String::new();
    match filter {
        Some(f) => out.push_str(&format!("No files match filter `{f}`.\n")),
        None => out.push_str("No files match.\n"),
    }
    out.push_str(&format!(
        "project_root: {}\n",
        ctx.session.project_root.display()
    ));
    out.push_str(&format!("cwd: {}\n", ctx.cwd.display()));
    if let Some(f) = filter {
        out.push_str(&format!("filter: {f}\n"));
    } else {
        out.push_str("filter: <none>\n");
    }
    out.push_str(&format!("fs_files: {fs_files}\n"));
    out.push_str(&format!("indexed_files: {indexed_files}\n"));
    if fs_files == 0 {
        out.push_str("empty_reason: zero discovered files\n");
        out.push_str(
            "hint: verify the project root/cwd; fall back to `rg --files` or `fd` if the filesystem walk is unexpectedly empty.",
        );
    } else if filter.is_some() {
        out.push_str("empty_reason: `path` filter excluded all discovered files\n");
        out.push_str("hint: run `tree` without `path` or use a different subtree.");
    } else {
        out.push_str("empty_reason: no output rows after discovery\n");
        out.push_str(
            "hint: verify the project root/cwd; fall back to `rg --files` or `fd` if the filesystem walk is unexpectedly empty.",
        );
    }
    out
}

// ---- outline ---------------------------------------------------------------

pub struct OutlineTool;

#[async_trait]
impl Tool for OutlineTool {
    fn name(&self) -> &str {
        "outline"
    }
    fn description(&self) -> &str {
        "Show a file's symbols and imports in line order; regex fallback for unknown languages"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Get a structural outline of one file — its functions, types, methods, and imports \
             in source order with line numbers — without reading the whole file. Use this to see \
             a file's shape and jump straight to the right line with a ranged `read`, instead of \
             `cat | head` in `bash` or paging the whole file. Falls back to a regex scan for \
             languages cockpit can't fully parse."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "File `path` to outline" }
            },
            "required": ["path"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Path to the single source file to outline, relative to the project root or absolute" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`path` is required"))?;
        // Native-tool boundary check (sandboxing part 2): the regex
        // fallback below reads the file off disk, so an out-of-cwd path
        // must escalate first.
        crate::tools::sandbox::check_native_access(
            ctx,
            &crate::tools::common::resolve(path_arg, &ctx.cwd),
        )
        .await?;
        let rel = rel_path(path_arg, ctx);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let (symbols, imports, language) = index.outline_rows(&rel)?;
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);

        // Unknown / not-indexed language → regex fallback (never errors).
        if language.is_empty() || language == "unknown" {
            let abs = crate::tools::common::resolve(path_arg, &ctx.cwd);
            let body = match std::fs::read_to_string(&abs) {
                Ok(b) => b,
                Err(e) => {
                    return Err(invalid_input(format!("read `{rel}`: {e}")));
                }
            };
            writer.writeln(&format!(
                "{rel} (unknown language — regex outline, may be incomplete)"
            ));
            let hits = regex_outline(&body);
            if hits.is_empty() {
                writer.writeln("  (no definitions matched)");
            }
            for (name, line) in hits {
                if !writer.writeln(&format!("  {line}: {name}")) {
                    break;
                }
            }
            return Ok(finish(writer, "\n... [truncated]\n"));
        }

        writer.writeln(&format!("{rel} ({language})"));
        if !imports.is_empty() {
            writer.writeln("imports:");
            for (target, line) in &imports {
                if !writer.writeln(&format!("  {line}: {target}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if !symbols.is_empty() {
            writer.writeln("symbols:");
            for s in &symbols {
                let vis = s
                    .visibility
                    .as_deref()
                    .map(|v| format!("{v} "))
                    .unwrap_or_default();
                let parent = s
                    .parent
                    .as_deref()
                    .map(|p| format!("{p}."))
                    .unwrap_or_default();
                let span = if s.end_line > s.line {
                    format!("{}-{}", s.line, s.end_line)
                } else {
                    s.line.to_string()
                };
                // Prefer the captured signature (first source line) for
                // callables; fall back to the synthesized form otherwise.
                let sig = match (s.kind.as_str(), &s.signature) {
                    ("function" | "method", Some(sig)) if !sig.is_empty() => {
                        format!("{vis}{}", sig.trim())
                    }
                    _ => format!("{vis}{} {parent}{}", s.kind, s.name),
                };
                if !writer.writeln(&format!("  {span}: {sig}")) {
                    break;
                }
            }
        }
        if symbols.is_empty() && imports.is_empty() {
            writer.writeln("  (no symbols or imports)");
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}

// ---- symbol_find -----------------------------------------------------------

pub struct SymbolFindTool;

#[async_trait]
impl Tool for SymbolFindTool {
    fn name(&self) -> &str {
        "symbol_find"
    }
    fn description(&self) -> &str {
        "Find symbol definitions by name (exact or prefix), optionally filtered by kind"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Find where a symbol is DEFINED — function, struct, class, method — by name across \
             the indexed codebase, returning the file + line of each definition. Use this to \
             answer \"where is X defined?\" instead of `bash`/`grep`: it returns definitions only, \
             not every mention. Matches `name` as a prefix by default; set `exact` for an exact \
             name and `kind` to narrow. To find every USE of a name instead, use `word`."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name":   { "type": "string", "description": "Symbol name or prefix" },
                "exact":  { "type": "boolean", "description": "Exact-match toggle (default prefix match)" },
                "kind":   { "type": "string", "description": "Kind filter (function/struct/class/method/...)" }
            },
            "required": ["name"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "name":   { "type": "string", "description": "The symbol name (or, by default, name prefix) to find the definition of" },
                "exact":  { "type": "boolean", "description": "When true, match `name` exactly instead of as a prefix; defaults to prefix matching for discovery" },
                "kind":   { "type": "string", "description": "Optional symbol-kind filter, e.g. `function`, `struct`, `class`, `method`; omit to match any kind" }
            },
            "required": ["name"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let exact = args.get("exact").and_then(Value::as_bool).unwrap_or(false);
        let kind = args.get("kind").and_then(Value::as_str);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let mut hits = index.symbol_find(name, exact, kind)?;
        if hits.is_empty() {
            return Ok(ToolOutput::text(format!("No symbol matches `{name}`.")));
        }
        // Centrality ranking (additive, default-on, config-disablable):
        // when a name resolves to multiple definitions, surface the most
        // central first; tie-break on the existing (path, line) order. The
        // SET of hits is unchanged — only order — so recall is identical to
        // the disabled path.
        if crate::config::extended::resolve_centrality_ranking(&ctx.cwd) {
            let scores = index.centrality_scores()?;
            rank_symbol_hits(&mut hits, &scores);
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for s in &hits {
            let parent = s
                .parent
                .as_deref()
                .map(|p| format!("{p}."))
                .unwrap_or_default();
            let line = format!("{}:{} {} {parent}{}", s.path, s.line, s.kind, s.name);
            if !writer.writeln(&line) {
                break;
            }
        }
        Ok(finish(
            writer,
            "\n... [truncated; narrow with `exact` or `kind`]\n",
        ))
    }
}

/// Reorder symbol hits by descending centrality (additive ranking,
/// Surface 1). A stable sort keyed on the rank multiplier preserves the
/// incoming `(path, line)` order as the tie-break, so the SET of hits is
/// untouched — only order changes. A path absent from `scores` ranks as
/// multiplier 1 (no change).
fn rank_symbol_hits(hits: &mut [crate::intel::SymbolRow], scores: &HashMap<String, f64>) {
    hits.sort_by(|a, b| {
        let ma =
            crate::intel::callgraph::rank_multiplier(scores.get(&a.path).copied().unwrap_or(0.0));
        let mb =
            crate::intel::callgraph::rank_multiplier(scores.get(&b.path).copied().unwrap_or(0.0));
        // Descending by multiplier; NaN-safe (scores are finite).
        mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
    });
}

// ---- word ------------------------------------------------------------------

pub struct WordTool;

#[async_trait]
impl Tool for WordTool {
    fn name(&self) -> &str {
        "word"
    }
    fn description(&self) -> &str {
        "List files and lines where an identifier token appears, from the index"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Find every place an identifier TOKEN appears across the codebase — all uses, not \
             just the definition — returning the file + line of each. Use this to trace where a \
             function/variable/type is referenced before you change it, instead of `bash`/`grep`. \
             Whole-token matches from the index, not substrings or regex; for general-text/regex \
             use `search`, for the definition only use `symbol_find`. Set `case_insensitive` to \
             ignore case."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "token":            { "type": "string", "description": "Identifier token to look up" },
                "case_insensitive": { "type": "boolean", "description": "Case-insensitive match toggle" }
            },
            "required": ["token"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "token":            { "type": "string", "description": "The exact identifier token to find uses of; matched as a whole word, not a substring" },
                "case_insensitive": { "type": "boolean", "description": "When true, match the token regardless of letter case; defaults to case-sensitive" }
            },
            "required": ["token"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let token = args
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`token` is required"))?;
        let ci = args
            .get("case_insensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let grouped = index.word_hits(token, ci)?;
        if grouped.is_empty() {
            return Ok(ToolOutput::text(format!(
                "`{token}` not found in the index."
            )));
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for (path, lines) in &grouped {
            let joined = lines
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join(",");
            if !writer.writeln(&format!("{path}: {joined}")) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}

// ---- deps ------------------------------------------------------------------

pub struct DepsTool;

#[async_trait]
impl Tool for DepsTool {
    fn name(&self) -> &str {
        "deps"
    }
    fn description(&self) -> &str {
        "Show a file's resolved import dependencies forward/reverse within a hop limit"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "See how one file connects to the rest of the codebase through imports: `forward` = \
             files it depends on, `reverse` = files that depend on it, `both` = both. Use \
             `reverse` to find everything you might break before changing a file — instead of \
             grepping for import lines; imports are resolved through cockpit's index, so this is \
             accurate. `hops` walks the graph that many levels deep (1 = direct neighbours)."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path":      { "type": "string", "x-cockpit-kind": "path", "description": "File `path` whose dependencies to walk" },
                "direction": { "type": "string", "description": "forward, reverse, or both (default both)" },
                "hops":      { "type": "integer", "description": "Max hops, 1-10 (default 1)" }
            },
            "required": ["path"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path":      { "type": "string", "x-cockpit-kind": "path", "description": "Path to the file whose import dependency graph to walk, relative to the project root or absolute" },
                "direction": { "type": "string", "description": "Which way to walk: `forward` (files this one imports), `reverse` (files that import this one), or `both`; defaults to `both`" },
                "hops":      { "type": "integer", "description": "How many levels deep to follow the graph, 1-10; defaults to 1 (direct neighbours only)" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`path` is required"))?;
        let rel = rel_path(path_arg, ctx);
        let direction = args
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("both");
        let hops = args
            .get("hops")
            .and_then(Value::as_u64)
            .map(|h| h.clamp(1, 10) as usize)
            .unwrap_or(1);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let edges = index.dep_edges()?;
        // forward: importer → importee; reverse: importee → importer.
        let mut forward: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut unresolved: Vec<&DepEdge> = Vec::new();
        for e in &edges {
            match &e.importee {
                Some(imp) => {
                    forward.entry(&e.importer).or_default().push(imp);
                    reverse.entry(imp).or_default().push(&e.importer);
                }
                None if e.importer == rel => unresolved.push(e),
                None => {}
            }
        }

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        writer.writeln(&format!("deps for {rel} (hops={hops})"));

        if direction == "forward" || direction == "both" {
            let reached = bfs(&forward, &rel, hops);
            writer.writeln(&format!("forward ({}):", reached.len()));
            for (dist, p) in &reached {
                if !writer.writeln(&format!("  [{dist}] {p}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if direction == "reverse" || direction == "both" {
            let reached = bfs(&reverse, &rel, hops);
            writer.writeln(&format!("reverse ({}):", reached.len()));
            for (dist, p) in &reached {
                if !writer.writeln(&format!("  [{dist}] {p}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if !unresolved.is_empty() {
            writer.writeln(&format!("unresolved imports ({}):", unresolved.len()));
            for e in &unresolved {
                if !writer.writeln(&format!("  {}: {}", e.line, e.raw_target)) {
                    break;
                }
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}

/// Shortest-distance BFS over an adjacency map, capped at `max_hops`.
/// Returns `(distance, node)` pairs (excludes the start node), sorted by
/// distance then path.
fn bfs<'a>(
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

// ---- change_impact ---------------------------------------------------------

pub struct ChangeImpactTool;

type HunkMap = HashMap<String, (Vec<(i64, i64)>, bool)>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChangedFile {
    status: String,
    path: String,
    old_path: Option<String>,
    ranges: Vec<(i64, i64)>,
    binary: bool,
    conflicted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RiskTier {
    Low,
    Medium,
    High,
}

struct RiskSignals {
    centrality: f64,
    callers: usize,
    calls: usize,
    has_reverse_deps: bool,
    has_forward_deps: bool,
    include_tests: bool,
}

impl RiskTier {
    fn as_str(self) -> &'static str {
        match self {
            RiskTier::Low => "low",
            RiskTier::Medium => "medium",
            RiskTier::High => "high",
        }
    }
}

#[async_trait]
impl Tool for ChangeImpactTool {
    fn name(&self) -> &str {
        "change_impact"
    }
    fn description(&self) -> &str {
        "Summarize git diff blast-radius hints using Cockpit's code-intelligence index"
    }
    fn defensive_description(&self) -> Option<String> {
        Some("Read-only impact hints for current git changes or a ref range. Combines changed files/hunks with indexed symbols, import reverse-deps, call graph, and centrality. Heuristic, not a proof; never stages, writes, or runs tests.".to_string())
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "base": { "type": "string", "description": "Optional git ref to diff against. Defaults to the working tree/index changes" },
                "target": { "type": "string", "description": "Optional git ref when base is set. Defaults to HEAD" },
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Optional path filter relative to the project root" },
                "depth": { "type": "integer", "description": "Dependency/call traversal depth, 1-3. Defaults to 1" },
                "include_tests": { "type": "boolean", "description": "Whether test files should contribute to risk. Defaults to true" }
            }
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let Some(git_root) = crate::git::find_worktree_root(&ctx.cwd) else {
            return Ok(ToolOutput::text(format!(
                "change_impact: no git worktree at {}\nimpact hints unavailable until this project is in a git repository.",
                ctx.cwd.display()
            )));
        };
        let base = args
            .get("base")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let target = args
            .get("target")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let path_filter = change_path_filter(args.get("path"), ctx)?;
        let depth = args
            .get("depth")
            .and_then(Value::as_u64)
            .map(|d| d.clamp(1, 3) as usize)
            .unwrap_or(1);
        let include_tests = args
            .get("include_tests")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if let Some(r) = base {
            reject_git_ref("base", r)?;
        }
        if let Some(r) = target {
            reject_git_ref("target", r)?;
        }
        let diff_label = match (base, target) {
            (None, _) => "working tree/index vs HEAD".to_string(),
            (Some(b), None) => format!("{b}..HEAD"),
            (Some(b), Some(t)) => format!("{b}..{t}"),
        };

        let mut changed = load_changed_files(&git_root, base, target, path_filter.as_deref())?;
        if base.is_none() {
            merge_untracked_and_conflicts(&git_root, &mut changed, path_filter.as_deref())?;
        }
        changed.sort_by(|a, b| a.path.cmp(&b.path).then(a.status.cmp(&b.status)));
        changed.dedup_by(|a, b| a.path == b.path && a.status == b.status);
        if changed.is_empty() {
            return Ok(ToolOutput::text(format!(
                "change_impact: impact hints\ndiff: {diff_label}\nfiles: none\nnext: no changed files matched this request."
            )));
        }

        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let dep_edges = index.dep_edges()?;
        let centrality = index.centrality_scores()?;
        let changed_paths: HashSet<String> = changed.iter().map(|f| f.path.clone()).collect();
        let mut file_symbols: HashMap<String, Vec<SymbolRow>> = HashMap::new();
        for file in &changed {
            if matches!(file.status.as_str(), "D") || file.binary || file.conflicted {
                continue;
            }
            let (symbols, _imports, _lang) = index.outline_rows(&file.path)?;
            file_symbols.insert(file.path.clone(), symbols);
        }

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        writer.writeln("change_impact: impact hints (heuristic, not a safety proof)");
        writer.writeln(&format!("diff: {diff_label}"));
        if let Some(path) = &path_filter {
            writer.writeln(&format!("path: {path}"));
        }
        writer.writeln(&format!("depth: {depth}"));
        writer.writeln("files:");
        let mut changed_symbols: Vec<(SymbolRow, RiskTier, usize, usize)> = Vec::new();
        for file in changed.iter().take(50) {
            let symbols = file_symbols.get(&file.path).cloned().unwrap_or_default();
            let overlapping = overlapping_symbols(&symbols, &file.ranges);
            let reverse = reverse_deps(&dep_edges, &file.path, depth, path_filter.as_deref());
            let forward = forward_deps(&dep_edges, &file.path, depth, path_filter.as_deref());
            let file_score = centrality.get(&file.path).copied().unwrap_or(0.0);
            let callers = overlapping
                .iter()
                .map(|s| {
                    index
                        .impact_callers(&s.path, s.line)
                        .unwrap_or_default()
                        .len()
                })
                .sum::<usize>();
            let calls = overlapping
                .iter()
                .map(|s| index.impact_calls(&s.name).unwrap_or_default().len())
                .sum::<usize>();
            let risk = risk_for_file(
                file,
                &overlapping,
                RiskSignals {
                    centrality: file_score,
                    callers,
                    calls,
                    has_reverse_deps: !reverse.is_empty(),
                    has_forward_deps: !forward.is_empty(),
                    include_tests,
                },
            );
            let mut details = Vec::new();
            if let Some(old) = &file.old_path {
                details.push(format!("from {old}"));
            }
            if file.binary {
                details.push("binary".to_string());
            }
            if file.conflicted {
                details.push("conflicted".to_string());
            }
            if !file.ranges.is_empty() {
                details.push(format!("ranges {}", format_ranges(&file.ranges)));
            }
            if file_score > 0.0 {
                details.push(format!("centrality {:.2}", file_score));
            }
            if !reverse.is_empty() {
                details.push(format!("reverse_deps {}", reverse.len()));
            }
            if callers > 0 {
                details.push(format!("callers {callers}"));
            }
            let suffix = if details.is_empty() {
                String::new()
            } else {
                format!(" ({})", details.join(", "))
            };
            if !writer.writeln(&format!(
                "  {} {} risk={}{}",
                file.status,
                file.path,
                risk.as_str(),
                suffix
            )) {
                return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
            }
            for symbol in overlapping {
                let sc = centrality.get(&symbol.path).copied().unwrap_or(0.0);
                let sym_callers = index
                    .impact_callers(&symbol.path, symbol.line)
                    .unwrap_or_default();
                let sym_calls = index.impact_calls(&symbol.name).unwrap_or_default();
                let sym_risk = risk_for_symbol(
                    &symbol,
                    sc,
                    sym_callers.len(),
                    sym_calls.len(),
                    include_tests,
                );
                changed_symbols.push((symbol, sym_risk, sym_callers.len(), sym_calls.len()));
            }
        }
        if changed.len() > 50 {
            writer.writeln(&format!(
                "  ... [{} more changed files omitted]",
                changed.len() - 50
            ));
        }

        if changed_symbols.is_empty() {
            writer.writeln("symbols: none matched changed hunks");
        } else {
            writer.writeln("symbols:");
            changed_symbols.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| a.0.path.cmp(&b.0.path))
                    .then(a.0.line.cmp(&b.0.line))
                    .then(a.0.name.cmp(&b.0.name))
            });
            for (sym, risk, callers, calls) in changed_symbols.iter().take(80) {
                let sig = sym.signature.as_deref().unwrap_or(&sym.name);
                if !writer.writeln(&format!(
                    "  {}:{}-{} {} {} risk={} callers={} calls={}",
                    sym.path,
                    sym.line,
                    sym.end_line,
                    sym.kind,
                    sig,
                    risk.as_str(),
                    callers,
                    calls
                )) {
                    return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
                }
            }
            if changed_symbols.len() > 80 {
                writer.writeln(&format!(
                    "  ... [{} more symbols omitted]",
                    changed_symbols.len() - 80
                ));
            }
        }

        writer.writeln("reverse dependencies:");
        let mut any_reverse = false;
        for file in &changed {
            for (_dist, dep) in reverse_deps(&dep_edges, &file.path, depth, path_filter.as_deref())
                .into_iter()
                .take(40)
            {
                any_reverse = true;
                if !writer.writeln(&format!("  {} <- {}", file.path, dep)) {
                    return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
                }
            }
        }
        if !any_reverse {
            writer.writeln("  none");
        }

        writer.writeln("call context:");
        let mut any_call = false;
        for (sym, _risk, _callers, _calls) in changed_symbols.iter().take(20) {
            for (caller_file, caller_line, caller_symbol) in index
                .impact_callers(&sym.path, sym.line)
                .unwrap_or_default()
                .into_iter()
                .take(20)
            {
                if path_filter.as_deref().is_some_and(|p| {
                    !path_matches_filter(&caller_file, p) && !changed_paths.contains(&sym.path)
                }) {
                    continue;
                }
                any_call = true;
                let in_sym = caller_symbol
                    .map(|s| format!(" in {s}"))
                    .unwrap_or_default();
                if !writer.writeln(&format!(
                    "  caller {}:{}{} -> {}:{} {}",
                    caller_file, caller_line, in_sym, sym.path, sym.line, sym.name
                )) {
                    return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
                }
            }
            for (callee, def_file, def_line) in index
                .impact_calls(&sym.name)
                .unwrap_or_default()
                .into_iter()
                .take(20)
            {
                if path_filter.as_deref().is_some_and(|p| {
                    !path_matches_filter(&def_file, p) && !changed_paths.contains(&sym.path)
                }) {
                    continue;
                }
                any_call = true;
                if !writer.writeln(&format!(
                    "  call {}:{} {} -> {}:{}",
                    sym.path, sym.line, callee, def_file, def_line
                )) {
                    return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
                }
            }
        }
        if !any_call {
            writer.writeln("  none");
        }
        writer.writeln(&format!("next: read narrow changed ranges; run `impact` for high-risk symbols; run `deps` reverse on high-risk files{}", path_filter.as_ref().map(|p| format!(" under `{p}`")).unwrap_or_default()));
        Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"))
    }
}

fn reject_git_ref(label: &str, value: &str) -> Result<()> {
    if value.starts_with('-') {
        return Err(invalid_input(format!("`{label}` must not start with `-`")));
    }
    Ok(())
}

fn change_path_filter(value: Option<&Value>, ctx: &ToolCtx) -> Result<Option<String>> {
    let Some(raw) = value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    if matches!(raw, "." | "./" | "/") {
        return Ok(None);
    }
    let resolved = crate::tools::common::resolve(raw, &ctx.cwd);
    let root = &ctx.session.project_root;
    let allowed = if resolved.exists() {
        let canonical_root = std::fs::canonicalize(root).map_err(|e| {
            invalid_input(format!(
                "project root `{}` is unusable: {e}",
                root.display()
            ))
        })?;
        let canonical = std::fs::canonicalize(&resolved)
            .map_err(|e| invalid_input(format!("cannot access `{raw}` within project: {e}")))?;
        canonical.starts_with(&canonical_root)
    } else {
        lexical_normalize(&resolved).starts_with(lexical_normalize(root))
    };
    if !allowed {
        return Err(invalid_input(format!(
            "`path` must stay inside project root: {raw}"
        )));
    }
    Ok(Some(rel_path(raw, ctx)))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn load_changed_files(
    git_root: &Path,
    base: Option<&str>,
    target: Option<&str>,
    path_filter: Option<&str>,
) -> Result<Vec<ChangedFile>> {
    let mut args: Vec<&str> = vec!["diff", "--name-status", "--find-renames"];
    let range;
    if let Some(base) = base {
        range = target
            .map(|t| format!("{base}..{t}"))
            .unwrap_or_else(|| format!("{base}..HEAD"));
        args.push(&range);
    } else {
        args.push("HEAD");
    }
    args.push("--");
    if let Some(path) = path_filter {
        args.push(path);
    }
    let out = crate::git::run_git(git_root, &args)?;
    if !out.success {
        return Err(invalid_input(format!(
            "invalid git diff request: {}",
            git_error_tail(&out.stderr, &out.stdout)
        )));
    }
    let mut files = parse_name_status(&out.stdout);
    let ranges = load_hunk_ranges(git_root, base, target, path_filter)?;
    for file in &mut files {
        if let Some((file_ranges, binary)) = ranges.get(&file.path) {
            file.ranges = file_ranges.clone();
            file.binary = *binary;
        }
    }
    Ok(files)
}

fn load_hunk_ranges(
    git_root: &Path,
    base: Option<&str>,
    target: Option<&str>,
    path_filter: Option<&str>,
) -> Result<HunkMap> {
    let mut args: Vec<&str> = vec!["diff", "--unified=0", "--find-renames"];
    let range;
    if let Some(base) = base {
        range = target
            .map(|t| format!("{base}..{t}"))
            .unwrap_or_else(|| format!("{base}..HEAD"));
        args.push(&range);
    } else {
        args.push("HEAD");
    }
    args.push("--");
    if let Some(path) = path_filter {
        args.push(path);
    }
    let out = crate::git::run_git(git_root, &args)?;
    if !out.success {
        return Err(invalid_input(format!(
            "invalid git diff request: {}",
            git_error_tail(&out.stderr, &out.stdout)
        )));
    }
    Ok(parse_unified_hunks(&out.stdout))
}

fn git_error_tail(stderr: &str, stdout: &str) -> String {
    let msg = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    msg.lines()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("; ")
}

fn parse_name_status(raw: &str) -> Vec<ChangedFile> {
    let mut out = Vec::new();
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split('\t').collect();
        let status = parts.first().copied().unwrap_or_default();
        if status.starts_with('R') && parts.len() >= 3 {
            out.push(ChangedFile {
                status: "R".to_string(),
                old_path: Some(parts[1].to_string()),
                path: parts[2].to_string(),
                ranges: Vec::new(),
                binary: false,
                conflicted: false,
            });
        } else if let Some(path) = parts.get(1) {
            out.push(ChangedFile {
                status: status.chars().next().unwrap_or('M').to_string(),
                old_path: None,
                path: (*path).to_string(),
                ranges: Vec::new(),
                binary: false,
                conflicted: false,
            });
        }
    }
    out
}

fn parse_unified_hunks(raw: &str) -> HunkMap {
    let mut out: HunkMap = HashMap::new();
    let mut current: Option<String> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            current = parse_diff_path_from_header(rest);
            if let Some(path) = &current {
                out.entry(path.clone()).or_default();
            }
            continue;
        }
        if let Some(path) = &current {
            if line.starts_with("Binary files") || line.starts_with("GIT binary patch") {
                out.entry(path.clone()).or_default().1 = true;
            } else if line.starts_with("@@")
                && let Some(range) = parse_new_hunk_range(line)
                && range.1 >= range.0
            {
                out.entry(path.clone()).or_default().0.push(range);
            }
        }
    }
    out
}

fn parse_diff_path_from_header(rest: &str) -> Option<String> {
    let mut parts = rest.split_whitespace();
    let _a = parts.next()?;
    let b = parts.next()?;
    b.strip_prefix("b/")
        .or_else(|| b.strip_prefix("a/"))
        .map(|p| p.to_string())
}

fn parse_new_hunk_range(line: &str) -> Option<(i64, i64)> {
    let plus = line.split_whitespace().find(|part| part.starts_with('+'))?;
    let spec = plus.trim_start_matches('+');
    let (start, count) = match spec.split_once(',') {
        Some((s, c)) => (s.parse::<i64>().ok()?, c.parse::<i64>().ok()?),
        None => (spec.parse::<i64>().ok()?, 1),
    };
    if count == 0 {
        None
    } else {
        Some((start, start + count - 1))
    }
}

fn merge_untracked_and_conflicts(
    git_root: &Path,
    changed: &mut Vec<ChangedFile>,
    path_filter: Option<&str>,
) -> Result<()> {
    let out = crate::git::run_git(git_root, &["status", "--porcelain=v1"])?;
    if !out.success {
        return Ok(());
    }
    for line in out.stdout.lines() {
        if line.len() < 4 {
            continue;
        }
        let code = &line[..2];
        let path = line[3..].split(" -> ").last().unwrap_or("").to_string();
        if path.is_empty() || path_filter.is_some_and(|f| !path_matches_filter(&path, f)) {
            continue;
        }
        if code == "??" {
            if changed.iter().any(|f| f.path == path) {
                continue;
            }
            let lines = count_lines(&git_root.join(&path));
            changed.push(ChangedFile {
                status: "A".to_string(),
                old_path: None,
                path,
                ranges: if lines == 0 {
                    Vec::new()
                } else {
                    vec![(1, lines as i64)]
                },
                binary: false,
                conflicted: false,
            });
        } else if code.contains('U') || matches!(code, "AA" | "DD") {
            if let Some(existing) = changed.iter_mut().find(|f| f.path == path) {
                existing.conflicted = true;
            } else {
                changed.push(ChangedFile {
                    status: "U".to_string(),
                    old_path: None,
                    path,
                    ranges: Vec::new(),
                    binary: false,
                    conflicted: true,
                });
            }
        }
    }
    Ok(())
}

fn overlapping_symbols(symbols: &[SymbolRow], ranges: &[(i64, i64)]) -> Vec<SymbolRow> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut out = symbols
        .iter()
        .filter(|s| {
            ranges
                .iter()
                .any(|(start, end)| s.line <= *end && s.end_line >= *start)
        })
        .cloned()
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.line.cmp(&b.line).then(a.name.cmp(&b.name)));
    out
}

fn reverse_deps(
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

fn forward_deps(
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

fn risk_for_file(file: &ChangedFile, symbols: &[SymbolRow], signals: RiskSignals) -> RiskTier {
    if !signals.include_tests && is_test_path(&file.path) {
        return RiskTier::Low;
    }
    if file.conflicted
        || signals.centrality > 0.0
        || signals.callers > 0
        || signals.has_reverse_deps
    {
        RiskTier::High
    } else if !symbols.is_empty()
        || signals.calls > 0
        || signals.has_forward_deps
        || matches!(file.status.as_str(), "D" | "R")
    {
        RiskTier::Medium
    } else {
        RiskTier::Low
    }
}

fn risk_for_symbol(
    symbol: &SymbolRow,
    centrality: f64,
    callers: usize,
    calls: usize,
    include_tests: bool,
) -> RiskTier {
    if !include_tests && is_test_path(&symbol.path) {
        return RiskTier::Low;
    }
    let public = symbol
        .visibility
        .as_deref()
        .is_some_and(|v| v.contains("pub"));
    if centrality > 0.0 || callers > 0 {
        RiskTier::High
    } else if calls > 0 || public {
        RiskTier::Medium
    } else {
        RiskTier::Low
    }
}

fn is_test_path(path: &str) -> bool {
    path.contains("/tests/")
        || path.ends_with("_test.rs")
        || path.ends_with(".test.ts")
        || path.ends_with(".spec.ts")
}
fn path_matches_filter(path: &str, filter: &str) -> bool {
    path == filter || path.starts_with(&format!("{filter}/"))
}
fn format_ranges(ranges: &[(i64, i64)]) -> String {
    ranges
        .iter()
        .take(8)
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

// ---- hot -------------------------------------------------------------------

pub struct HotTool;

#[async_trait]
impl Tool for HotTool {
    fn name(&self) -> &str {
        "hot"
    }
    fn description(&self) -> &str {
        "List the most recently modified tracked files by mtime"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "List the files that were edited most recently, newest first, by modification time. \
             Use this to orient on a task quickly — recently-touched files are usually where the \
             active work is — or to find what changed last. `limit` caps how many to return. \
             This is a ranking by recency, not a snapshot of any one file."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "description": "Max files (default 20)" }
            }
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "description": "Maximum number of recently-modified files to return; defaults to 20" }
            }
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| l.clamp(1, 500) as usize)
            .unwrap_or(20);
        // Pure-FS: no index. Gitignore walk, sort by mtime desc.
        let root = &ctx.session.project_root;
        let mut files: Vec<(std::time::SystemTime, String, u64)> = Vec::new();
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
            let abs = dent.path();
            let Ok(rel) = abs.strip_prefix(root) else {
                continue;
            };
            if let Ok(meta) = std::fs::metadata(abs)
                && let Ok(mtime) = meta.modified()
            {
                files.push((mtime, rel.to_string_lossy().replace('\\', "/"), meta.len()));
            }
        }
        files.sort_by_key(|f| std::cmp::Reverse(f.0));
        files.truncate(limit);
        if files.is_empty() {
            return Ok(ToolOutput::text("No tracked files.".to_string()));
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for (_, rel, size) in &files {
            if !writer.writeln(&format!("{rel}  {size}b")) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated; lower `limit`]\n"))
    }
}

// ---- circular --------------------------------------------------------------

pub struct CircularTool;

#[async_trait]
impl Tool for CircularTool {
    fn name(&self) -> &str {
        "circular"
    }
    fn description(&self) -> &str {
        "Detect import cycles via strongly-connected components of the dependency graph"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Find import cycles in the codebase: groups of files that depend on each other \
             directly or transitively. Use this when you suspect a circular-dependency problem, \
             or before a refactor that moves code between modules, to see which files are \
             tangled together. Takes no arguments — it analyses the whole project dependency \
             graph and reports each cycle it finds."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({ "type": "object", "properties": {} }))
    }

    async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let edges = index.dep_edges()?;

        // Build the resolved graph (importee NOT NULL).
        let mut nodes: Vec<String> = Vec::new();
        let mut idx: HashMap<String, usize> = HashMap::new();
        let mut adj: Vec<Vec<usize>> = Vec::new();
        let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
        for e in &edges {
            if let Some(importee) = &e.importee {
                let a = intern(&e.importer, &mut nodes, &mut idx, &mut adj);
                let b = intern(importee, &mut nodes, &mut idx, &mut adj);
                if seen_edges.insert((a, b)) {
                    adj[a].push(b);
                }
            }
        }

        let sccs = tarjan_scc(&adj);
        // Keep cycles only: SCC size > 1, or a self-loop.
        let mut cycles: Vec<Vec<usize>> = Vec::new();
        for comp in sccs {
            if comp.len() > 1 {
                cycles.push(comp);
            } else if comp.len() == 1 {
                let n = comp[0];
                if adj[n].contains(&n) {
                    cycles.push(comp);
                }
            }
        }
        if cycles.is_empty() {
            return Ok(ToolOutput::text("No import cycles found.".to_string()));
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        writer.writeln(&format!("{} cycle(s):", cycles.len()));
        for comp in &cycles {
            let mut names: Vec<&str> = comp.iter().map(|&i| nodes[i].as_str()).collect();
            names.sort();
            let mut chain = names.clone();
            chain.push(names[0]);
            if !writer.writeln(&format!("  {}", chain.join(" -> "))) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}

/// Intern a node name into the (nodes, index, adjacency) tables,
/// returning its dense index.
fn intern(
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
fn tarjan_scc(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
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

// ---- search ----------------------------------------------------------------

pub struct SearchTool;

#[async_trait]
impl Tool for SearchTool {
    fn name(&self) -> &str {
        "search"
    }
    fn description(&self) -> &str {
        "Budgeted structured regex search across the repo (ripgrep-backed)"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "When you would reach for `rg`/`grep` in `bash`, call `search` instead — same ripgrep \
             power, but budget-capped so it won't flood your context. It returns `file:line` \
             matches for a regular expression. Use it for any text/pattern/comment/string. \
             Narrow with `path`/`glob`, add `context` for surrounding lines. For one specific \
             identifier the precise tools are better and cheaper: `symbol_find` for where it is \
             DEFINED, `word` for every USE."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern":          { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "Regex to search for" },
                "path":             { "type": "string", "x-cockpit-kind": "path", "description": "`path` filter relative to project root" },
                "ignore_case":      { "type": "boolean", "description": "Case-insensitive match toggle" },
                "context":          { "type": "integer", "description": "Context lines around each match" },
                "glob":             { "type": "string", "description": "`glob` include filter (e.g. `*.rs`)" }
            },
            "required": ["pattern"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern":          { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "The regular expression to search for across file contents" },
                "path":             { "type": "string", "x-cockpit-kind": "path", "description": "Optional path to restrict the search to, relative to the project root; omit to search the whole repo" },
                "ignore_case":      { "type": "boolean", "description": "When true, match case-insensitively; defaults to case-sensitive" },
                "context":          { "type": "integer", "description": "Number of lines of surrounding context to include around each match; defaults to none" },
                "glob":             { "type": "string", "description": "Optional glob to include only matching files, e.g. `*.rs` or `src/**`" }
            },
            "required": ["pattern"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let pattern = args
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`pattern` is required"))?;
        let path = args.get("path").and_then(Value::as_str);
        let ignore_case = args
            .get("ignore_case")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let context = args
            .get("context")
            .and_then(Value::as_u64)
            .map(|c| c.min(10));
        let glob = args.get("glob").and_then(Value::as_str);

        let root = ctx.session.project_root.clone();
        let search_path = match path {
            Some(p) => crate::tools::common::resolve(p, &ctx.cwd),
            None => root.clone(),
        };
        // Native-tool boundary check (sandboxing part 2): a `path` filter
        // pointing outside cwd + session tmp must escalate before the
        // search reads any file contents there.
        crate::tools::sandbox::check_native_access(ctx, &search_path).await?;
        // Distinguish dir / single-file / missing up front so a file path
        // searches just that file (no silent widening to the parent) and a
        // missing path returns a legible error instead of a raw OS one.
        let target = match path {
            Some(p) => match std::fs::metadata(&search_path) {
                Ok(m) if m.is_dir() => SearchTarget::Dir(search_path),
                Ok(_) => SearchTarget::File(search_path),
                Err(_) => {
                    return Err(invalid_input(format!(
                        "`path` `{p}` does not exist relative to the project root"
                    )));
                }
            },
            None => SearchTarget::Dir(search_path),
        };
        let single_file = matches!(target, SearchTarget::File(_));
        let have_rg = which::which("rg").is_ok();
        let raw = run_search(have_rg, pattern, &target, ignore_case, context, glob).await?;

        let body = if have_rg {
            format_rg_json(&raw, &root)
        } else {
            format_grep(&raw, &root)
        };
        // Hint, attached as a clearly separated note (never interleaved with
        // match data), nudging callers toward a directory scope or
        // `read`/`grep` for single-file lookups.
        const SINGLE_FILE_NOTE: &str = "\nNOTE: searched a single file; pass a directory to scope a subtree, \
             or use `read`/`grep` for single-file lookups.\n";
        if body.is_empty() {
            let mut msg = format!("No matches for `{pattern}`.");
            if single_file {
                msg.push_str(SINGLE_FILE_NOTE);
            }
            return Ok(ToolOutput::text(msg));
        }

        // Centrality ranking (Surface 1, additive, default-on,
        // config-disablable): reorder the match groups so the highest-
        // centrality files' matches are emitted FIRST. This happens BEFORE
        // truncation so the most-central matches survive the budget cap.
        // It is a pure reorder — the SET of emitted lines and `file:line`
        // format are unchanged, so recall under the cap is identical with
        // ranking on vs off (verified by the additive test). When disabled
        // the body is emitted verbatim in rg/grep file order.
        let ranked_body = if crate::config::extended::resolve_centrality_ranking(&ctx.cwd) {
            let index = index_of(ctx);
            index.ensure_fresh().await?;
            let scores = index.centrality_scores()?;
            rank_search_body(&body, &scores, path)
        } else {
            body
        };

        let (render_body, thinned) = thin_line_output(&ranked_body, pattern, ThinLimits::default());
        let mut writer = BudgetedWriter::new(SEARCH_TOKEN_CAP);
        for line in render_body.lines() {
            if !writer.writeln(line) {
                break;
            }
        }
        let mut out = if thinned {
            let truncated = writer.is_truncated();
            let mut content = writer.into_string();
            if truncated {
                content.push_str(
                    "\n... [truncated; narrow the query or add a `path`/`glob` filter]\n",
                );
            }
            ToolOutput::truncated_text(content)
        } else {
            finish(
                writer,
                "\n... [truncated; narrow the query or add a `path`/`glob` filter]\n",
            )
        };
        if single_file {
            out.content.push_str(SINGLE_FILE_NOTE);
        }
        Ok(out)
    }
}

// ---- impact ----------------------------------------------------------------

pub struct ImpactTool;

#[async_trait]
impl Tool for ImpactTool {
    fn name(&self) -> &str {
        "impact"
    }
    fn description(&self) -> &str {
        "Show a symbol's callers and the calls in its own body, high-precision name-resolved"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Get the call-graph context of one symbol in a single call: its CALLERS (who calls \
             it, with file:line) and its CALLS (what its own body invokes, each resolved to a \
             definition's file:line). Use this to find the blast radius before you rename or \
             change a function — instead of grepping for the name and reading every hit. Only \
             high-confidence edges are shown: a call is reported when its name resolves to \
             exactly ONE definition; ambiguous or unresolved calls are omitted, never guessed. \
             Disambiguate with `path`/`kind` if the name is defined in several files."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "name",
            "properties": {
                "name": { "type": "string", "x-cockpit-aliases": ["symbol", "function", "fn"], "description": "Symbol name to analyze" },
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Defining file `path` filter when the name is ambiguous" },
                "kind": { "type": "string", "description": "Kind filter (function/struct/class/method/...)" }
            },
            "required": ["name"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "name",
            "properties": {
                "name": { "type": "string", "x-cockpit-aliases": ["symbol", "function", "fn"], "description": "The exact symbol name whose callers and calls to report" },
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Optional defining-file path to disambiguate when the name is defined in several files, relative to the project root or absolute" },
                "kind": { "type": "string", "description": "Optional symbol-kind filter, e.g. `function`, `struct`, `method`; omit to match any kind" }
            },
            "required": ["name"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .map(|p| rel_path(p, ctx));
        let kind = args.get("kind").and_then(Value::as_str);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let targets = index.impact_targets(name, path.as_deref(), kind)?;
        if targets.is_empty() {
            return Ok(ToolOutput::text(format!("No symbol matches `{name}`.")));
        }

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        // When the name still resolves to multiple definitions, report
        // each target's context separately (most-central first) so the
        // model isn't forced to disambiguate up front.
        let scores = index.centrality_scores()?;
        let mut targets = targets;
        targets.sort_by(|a, b| {
            let ma =
                crate::intel::callgraph::rank_multiplier(scores.get(&a.0).copied().unwrap_or(0.0));
            let mb =
                crate::intel::callgraph::rank_multiplier(scores.get(&b.0).copied().unwrap_or(0.0));
            mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
        });

        let multi = targets.len() > 1;
        for (tpath, tline, tkind) in &targets {
            if multi {
                writer.writeln(&format!("=== {name} ({tkind}) at {tpath}:{tline} ==="));
            } else {
                writer.writeln(&format!("{name} ({tkind}) at {tpath}:{tline}"));
            }

            let callers = index.impact_callers(tpath, *tline)?;
            if callers.is_empty() {
                writer.writeln("Callers: none");
            } else {
                writer.writeln(&format!("Callers ({}):", callers.len()));
                for (cf, cl, csym) in &callers {
                    let sym = csym
                        .as_deref()
                        .map(|s| format!(" in {s}"))
                        .unwrap_or_default();
                    if !writer.writeln(&format!("  {cf}:{cl}{sym}")) {
                        return Ok(finish(
                            writer,
                            "\n... [truncated; narrow the query with `path`/`kind`]\n",
                        ));
                    }
                }
            }

            let calls = index.impact_calls(name)?;
            if calls.is_empty() {
                writer.writeln("Calls: none");
            } else {
                writer.writeln(&format!("Calls ({}):", calls.len()));
                for (callee, df, dl) in &calls {
                    if !writer.writeln(&format!("  {callee} -> {df}:{dl}")) {
                        return Ok(finish(
                            writer,
                            "\n... [truncated; narrow the query with `path`/`kind`]\n",
                        ));
                    }
                }
            }
        }
        Ok(finish(
            writer,
            "\n... [truncated; narrow the query with `path`/`kind`]\n",
        ))
    }
}

/// Reorder a formatted `search` body (`path:line[:col][sep] text` records,
/// one per line) so the highest-centrality files' matches come first.
/// Groups records by file (preserving first-seen order and within-file
/// line order), then stable-sorts the groups by descending centrality
/// multiplier. A pure reorder: every input line appears exactly once in
/// the output, so recall is untouched.
///
/// `path_filter` is the optional `path` arg: when set, rg/grep ran with
/// cwd = the filter dir, so emitted paths are relative to it — we also try
/// `{path_filter}/{body_path}` against the (project-root-relative)
/// centrality map so the lookup still hits. Lines that don't parse to a
/// leading path keep their position with the preceding group.
fn rank_search_body(
    body: &str,
    scores: &HashMap<String, f64>,
    path_filter: Option<&str>,
) -> String {
    // Group lines by file in first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in body.lines() {
        let file = line.split_once(':').map(|(p, _)| p.to_string());
        let key = match file {
            Some(f) => {
                if !groups.contains_key(&f) {
                    order.push(f.clone());
                }
                current = Some(f.clone());
                f
            }
            // A line with no `:` (rare) attaches to the current group, or
            // starts a degenerate group keyed by itself.
            None => match &current {
                Some(c) => c.clone(),
                None => {
                    let k = line.to_string();
                    if !groups.contains_key(&k) {
                        order.push(k.clone());
                    }
                    current = Some(k.clone());
                    k
                }
            },
        };
        groups.entry(key).or_default().push(line.to_string());
    }

    // Centrality lookup: try the body path, then `{filter}/{path}`.
    let score_of = |file: &str| -> f64 {
        let trimmed = file.trim_start_matches("./");
        if let Some(s) = scores.get(trimmed) {
            return *s;
        }
        if let Some(pf) = path_filter {
            let pf = pf.trim_start_matches("./").trim_end_matches('/');
            let joined = format!("{pf}/{trimmed}");
            if let Some(s) = scores.get(&joined) {
                return *s;
            }
        }
        0.0
    };

    // Stable sort the groups by descending centrality multiplier; ties keep
    // first-seen (rg/grep) order.
    order.sort_by(|a, b| {
        let ma = crate::intel::callgraph::rank_multiplier(score_of(a));
        let mb = crate::intel::callgraph::rank_multiplier(score_of(b));
        mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut out = String::with_capacity(body.len());
    for file in &order {
        if let Some(lines) = groups.get(file) {
            for l in lines {
                out.push_str(l);
                out.push('\n');
            }
        }
    }
    out
}

/// Resolved search scope: a directory (cwd = dir, target = `.`) or a
/// single file (cwd = parent dir, target = file name). Splitting it this
/// way keeps `display_path` working — rg/grep emit paths relative to cwd.
enum SearchTarget {
    Dir(PathBuf),
    File(PathBuf),
}

/// Spawn `rg --json` (preferred) or `grep -rn` and return stdout.
async fn run_search(
    have_rg: bool,
    pattern: &str,
    target: &SearchTarget,
    ignore_case: bool,
    context: Option<u64>,
    glob: Option<&str>,
) -> Result<String> {
    // Run from a directory (cwd) and point the tool at one target so output
    // paths stay relative to cwd. For a file, cwd = parent and target =
    // file name; for a dir, cwd = dir and target = `.`.
    let (cwd, arg): (PathBuf, std::ffi::OsString) = match target {
        SearchTarget::Dir(dir) => (dir.clone(), std::ffi::OsString::from(".")),
        SearchTarget::File(file) => {
            let parent = file.parent().unwrap_or(Path::new(".")).to_path_buf();
            let name = file
                .file_name()
                .map(std::ffi::OsString::from)
                .unwrap_or_else(|| std::ffi::OsString::from("."));
            (parent, name)
        }
    };
    let mut cmd = if have_rg {
        let mut c = tokio::process::Command::new("rg");
        c.arg("--json")
            .arg("--line-number")
            .arg("--column")
            .arg("--no-heading")
            .arg("--color")
            .arg("never");
        if ignore_case {
            c.arg("--ignore-case");
        }
        if let Some(n) = context {
            c.arg("--context").arg(n.to_string());
        }
        if let Some(g) = glob {
            c.arg("--glob").arg(g);
        }
        c.arg("--").arg(pattern).arg(&arg);
        c
    } else {
        let mut c = tokio::process::Command::new("grep");
        c.arg("-rn");
        if ignore_case {
            c.arg("-i");
        }
        if let Some(n) = context {
            c.arg(format!("-C{n}"));
        }
        if let Some(g) = glob {
            c.arg(format!("--include={g}"));
        }
        c.arg("-e").arg(pattern).arg(&arg);
        c
    };
    cmd.current_dir(&cwd);
    let output = cmd
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawning search: {e}"))?;
    // rg/grep exit 1 means "no matches" — not an error.
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse rg's NDJSON stream into terse `path:line:col: text` records.
fn format_rg_json(stdout: &str, root: &Path) -> String {
    let mut out = String::new();
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ty = v.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "match" | "context" => {
                let data = match v.get("data") {
                    Some(d) => d,
                    None => continue,
                };
                let path = data
                    .get("path")
                    .and_then(|p| p.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let line_no = data.get("line_number").and_then(Value::as_u64).unwrap_or(0);
                let text = data
                    .get("lines")
                    .and_then(|l| l.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim_end_matches('\n');
                let col = data
                    .get("submatches")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(|m| m.get("start"))
                    .and_then(Value::as_u64)
                    .map(|c| c + 1);
                let disp = display_path(path, root);
                let sep = if ty == "context" { "-" } else { ":" };
                match col {
                    Some(c) => out.push_str(&format!("{disp}:{line_no}:{c}{sep} {text}\n")),
                    None => out.push_str(&format!("{disp}:{line_no}{sep} {text}\n")),
                }
            }
            _ => {}
        }
    }
    out
}

/// `grep -rn` output is already `path:line:text`; just normalize paths.
/// Known fallback limitation: when context is requested the grep fallback
/// uses `-C{n}`, whose context lines are `path-line-text` (dash separators)
/// — the `split_once(':')` below doesn't carry those separators cleanly.
fn format_grep(stdout: &str, root: &Path) -> String {
    let mut out = String::new();
    for line in stdout.lines() {
        if let Some((path, rest)) = line.split_once(':') {
            let disp = display_path(path, root);
            out.push_str(&format!("{disp}:{rest}\n"));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Make a path from search output relative + forward-slashed for display.
fn display_path(p: &str, root: &Path) -> String {
    let stripped = p.trim_start_matches("./");
    // rg/grep run with cwd=search_dir, so paths are already relative to
    // it; if `path` filter pointed below root, prepend nothing — the
    // model still gets a usable relative path. Absolute paths get
    // root-stripped.
    if let Ok(abs) = Path::new(p).strip_prefix(root) {
        abs.to_string_lossy().replace('\\', "/")
    } else {
        stripped.replace('\\', "/")
    }
}

// ---- shared FS helpers -----------------------------------------------------

/// Gitignore-aware list of `(rel, abs, size)` for every tracked file.
fn list_files(root: &Path) -> Vec<(String, PathBuf, u64)> {
    let mut out = Vec::new();
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
        let abs = dent.path().to_path_buf();
        let Ok(rel) = abs.strip_prefix(root) else {
            continue;
        };
        let size = std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0);
        out.push((rel.to_string_lossy().replace('\\', "/"), abs, size));
    }
    out
}

fn count_lines(abs: &Path) -> usize {
    match std::fs::read(abs) {
        Ok(b) if !b.contains(&0u8) => bytecount(&b),
        _ => 0,
    }
}

fn bytecount(b: &[u8]) -> usize {
    if b.is_empty() {
        return 0;
    }
    let nl = b.iter().filter(|&&c| c == b'\n').count();
    // Count a trailing partial line.
    if b.last() == Some(&b'\n') { nl } else { nl + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::common::test_ctx;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    #[tokio::test]
    async fn outline_unknown_language_uses_regex_fallback_without_erroring() {
        let tmp = tempfile::tempdir().unwrap();
        // `.foo` is an unknown extension; give it def-like lines.
        write(
            tmp.path(),
            "weird.foo",
            "function alpha() {}\nclass Beta {}\n",
        );
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({ "path": "weird.foo" });
        let out = OutlineTool.call(args, &ctx).await.unwrap();
        assert!(
            out.content.contains("unknown language"),
            "got: {}",
            out.content
        );
        assert!(out.content.contains("alpha"));
        assert!(out.content.contains("Beta"));
    }

    #[tokio::test]
    async fn tree_and_hot_list_unknown_language_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
        write(tmp.path(), "notes.foo", "anything\n");
        let ctx = test_ctx(tmp.path());

        let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();
        assert!(tree.content.contains("src/lib.rs"));
        assert!(tree.content.contains("notes.foo"));
        // The unknown file is visible but flagged not-indexed.
        assert!(tree.content.contains("notes.foo  unknown"));

        let hot = HotTool.call(serde_json::json!({}), &ctx).await.unwrap();
        assert!(hot.content.contains("notes.foo"));
        assert!(hot.content.contains("src/lib.rs"));
    }

    #[tokio::test]
    async fn tree_lists_files_including_unknown_language_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
        write(tmp.path(), "scratch.unknownext", "notes\n");
        let ctx = test_ctx(tmp.path());

        let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

        assert!(
            tree.content.contains("src/lib.rs  rust"),
            "{}",
            tree.content
        );
        assert!(
            tree.content.contains("scratch.unknownext  unknown"),
            "{}",
            tree.content
        );
    }

    #[tokio::test]
    async fn tree_filter_with_no_matches_reports_files_filter_and_hint() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
        let ctx = test_ctx(tmp.path());

        let tree = TreeTool
            .call(serde_json::json!({"path": "src/nope"}), &ctx)
            .await
            .unwrap();

        assert!(
            tree.content.contains("No files match filter `src/nope`."),
            "{}",
            tree.content
        );
        assert!(
            tree.content.contains("filter: src/nope"),
            "{}",
            tree.content
        );
        assert!(tree.content.contains("fs_files: 1"), "{}", tree.content);
        assert!(
            tree.content.contains("hint: run `tree` without `path`"),
            "{}",
            tree.content
        );
    }

    #[tokio::test]
    async fn tree_root_like_paths_normalize_to_repo_root_listing() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
        write(tmp.path(), "README.md", "# repo\n");
        let mut ctx = test_ctx(tmp.path());
        ctx.cwd = tmp.path().join("src");

        for args in [
            serde_json::json!({}),
            serde_json::json!({"path": ""}),
            serde_json::json!({"path": "."}),
            serde_json::json!({"path": "./"}),
            serde_json::json!({"path": "/"}),
            serde_json::json!({"path": tmp.path()}),
        ] {
            let tree = TreeTool.call(args, &ctx).await.unwrap();
            assert!(tree.content.contains("src/lib.rs"), "{}", tree.content);
            assert!(tree.content.contains("README.md"), "{}", tree.content);
            assert!(
                !tree.content.contains("No files match"),
                "root-like spellings must not trigger the empty diagnostic: {}",
                tree.content
            );
        }
    }

    #[tokio::test]
    async fn tree_empty_project_reports_root_cwd_counts_and_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

        assert!(tree.content.contains("project_root:"), "{}", tree.content);
        assert!(tree.content.contains("cwd:"), "{}", tree.content);
        assert!(tree.content.contains("filter: <none>"), "{}", tree.content);
        assert!(tree.content.contains("fs_files: 0"), "{}", tree.content);
        assert!(tree.content.contains("indexed_files:"), "{}", tree.content);
        assert!(
            tree.content
                .contains("hint: verify the project root/cwd; fall back to `rg --files`"),
            "{}",
            tree.content
        );
    }

    #[tokio::test]
    async fn symbol_find_and_word_round_trip_through_call() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "m.rs",
            "pub fn target_fn() { let target_fn = 1; }\n",
        );
        let ctx = test_ctx(tmp.path());

        let sf = SymbolFindTool
            .call(
                serde_json::json!({ "name": "target_fn", "exact": true }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(sf.content.contains("m.rs"));
        assert!(sf.content.contains("target_fn"));

        let w = WordTool
            .call(serde_json::json!({ "token": "target_fn" }), &ctx)
            .await
            .unwrap();
        assert!(w.content.contains("m.rs"));
    }

    #[test]
    fn tarjan_finds_simple_cycle() {
        // 0 -> 1 -> 2 -> 0, and 3 isolated.
        let adj = vec![vec![1], vec![2], vec![0], vec![]];
        let sccs = tarjan_scc(&adj);
        let cyc: Vec<_> = sccs.iter().filter(|c| c.len() > 1).collect();
        assert_eq!(cyc.len(), 1);
        assert_eq!(cyc[0].len(), 3);
    }

    #[test]
    fn tarjan_no_cycle() {
        let adj = vec![vec![1], vec![2], vec![]];
        let sccs = tarjan_scc(&adj);
        assert!(sccs.iter().all(|c| c.len() == 1));
    }

    #[test]
    fn bfs_respects_hop_limit() {
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        adj.insert("a", vec!["b"]);
        adj.insert("b", vec!["c"]);
        adj.insert("c", vec!["d"]);
        let one = bfs(&adj, "a", 1);
        assert_eq!(one, vec![(1, "b".to_string())]);
        let two = bfs(&adj, "a", 2);
        assert_eq!(two, vec![(1, "b".to_string()), (2, "c".to_string())]);
    }

    #[test]
    fn bytecount_counts_lines() {
        assert_eq!(bytecount(b""), 0);
        assert_eq!(bytecount(b"a\n"), 1);
        assert_eq!(bytecount(b"a\nb"), 2);
        assert_eq!(bytecount(b"a\nb\n"), 2);
    }

    #[tokio::test]
    async fn search_single_file_returns_matches_plus_note() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "src/tui/settings/mod.rs",
            "fn render_root() {}\nfn other() {}\n",
        );
        // A sibling file with the same pattern must NOT appear — proves we
        // searched just the one file, no widening to the parent dir.
        write(
            tmp.path(),
            "src/tui/settings/sibling.rs",
            "fn render_root() {}\n",
        );
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({
            "path": "src/tui/settings/mod.rs",
            "pattern": "fn render_root"
        });
        let out = SearchTool.call(args, &ctx).await.unwrap();
        // rg runs with cwd = the file's parent dir, so the emitted path is
        // relative to it (`mod.rs`) — the pre-existing display convention
        // for a below-root `path` filter.
        assert!(out.content.contains("mod.rs:1"), "got: {}", out.content);
        assert!(
            !out.content.contains("sibling.rs"),
            "single-file search must not widen to the parent dir; got: {}",
            out.content
        );
        assert!(
            out.content.contains("NOTE:"),
            "single-file result must carry the informational note; got: {}",
            out.content
        );
        // The note is separated from match data, never interleaved into a
        // `path:line:col:` record.
        assert!(!out.content.contains(":NOTE"), "got: {}", out.content);
    }

    #[tokio::test]
    async fn search_nonexistent_path_returns_clear_error() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({
            "path": "src/does/not/exist.rs",
            "pattern": "anything"
        });
        let err = SearchTool.call(args, &ctx).await.unwrap_err().to_string();
        assert!(
            err.contains("does not exist"),
            "expected a legible missing-path error, got: {err}"
        );
        assert!(
            !err.to_lowercase().contains("os error"),
            "must not surface a raw OS error, got: {err}"
        );
    }

    #[tokio::test]
    async fn search_directory_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/a.rs", "fn target_pat() {}\n");
        write(tmp.path(), "src/b.rs", "fn target_pat() {}\n");
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({ "path": "src", "pattern": "target_pat" });
        let out = SearchTool.call(args, &ctx).await.unwrap();
        // Paths are relative to the `src` filter dir (pre-existing convention).
        assert!(out.content.contains("a.rs:1"), "got: {}", out.content);
        assert!(out.content.contains("b.rs:1"), "got: {}", out.content);
        // No single-file note on a directory search.
        assert!(!out.content.contains("NOTE:"), "got: {}", out.content);
    }

    #[tokio::test]
    async fn search_thins_large_line_results_before_budgeting() {
        let tmp = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 1..=20 {
            if i == 11 {
                body.push_str("target panic failure\n");
            } else {
                body.push_str("target filler\n");
            }
        }
        write(tmp.path(), "src/lib.rs", &body);
        let ctx = test_ctx(tmp.path());
        let out = SearchTool
            .call(
                serde_json::json!({ "pattern": "target", "path": "src" }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(out.truncated, "thinning should mark the output truncated");
        assert!(out.content.contains("lib.rs:1:"), "got: {}", out.content);
        assert!(out.content.contains("lib.rs:20:"), "got: {}", out.content);
        assert!(
            out.content.contains("lib.rs:11:1: target panic failure")
                || out.content.contains("lib.rs:11: target panic failure"),
            "got: {}",
            out.content
        );
        assert!(
            out.content
                .contains("more matches in lib.rs omitted; narrow query or path"),
            "got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn context_pack_overview_on_multifile_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "src/lib.rs",
            "mod util;\npub fn main() {\n    util::helper();\n}\n",
        );
        write(tmp.path(), "src/util.rs", "pub fn helper() {}\n");
        write(tmp.path(), "script.py", "def runner():\n    pass\n");
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(serde_json::json!({ "kind": "overview", "limit": 8 }), &ctx)
            .await
            .unwrap();

        assert!(
            out.content.contains("context_pack: overview"),
            "{}",
            out.content
        );
        assert!(out.content.contains("languages:"), "{}", out.content);
        assert!(out.content.contains("rust"), "{}", out.content);
        assert!(out.content.contains("python"), "{}", out.content);
        assert!(out.content.contains("entry candidates:"), "{}", out.content);
        assert!(out.content.contains("src/lib.rs"), "{}", out.content);
        assert!(out.content.contains("next:"), "{}", out.content);
    }

    #[tokio::test]
    async fn context_pack_path_includes_outline_imports_and_reverse_deps() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "src/app.ts",
            "import { helper } from './util';\nexport function main() {\n    helper();\n}\n",
        );
        write(tmp.path(), "src/util.ts", "export function helper() {}\n");
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(
                serde_json::json!({ "target": "src/util.ts", "kind": "path", "depth": 1 }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("context_pack: path"),
            "{}",
            out.content
        );
        assert!(out.content.contains("path: src/util.ts"), "{}", out.content);
        assert!(out.content.contains("helper"), "{}", out.content);
        assert!(out.content.contains("reverse:"), "{}", out.content);
        assert!(out.content.contains("src/app.ts"), "{}", out.content);
        assert!(out.content.contains("suggested reads:"), "{}", out.content);
    }

    #[tokio::test]
    async fn context_pack_symbol_handles_multiple_candidates_and_call_context() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "a.rs",
            "pub fn helper() {}\npub fn target_alpha() {\n    helper();\n}\n",
        );
        write(tmp.path(), "b.rs", "pub fn target_beta() {}\n");
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(
                serde_json::json!({ "target": "target", "kind": "symbol" }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("context_pack: symbol"),
            "{}",
            out.content
        );
        assert!(out.content.contains("target_alpha"), "{}", out.content);
        assert!(out.content.contains("target_beta"), "{}", out.content);
        assert!(
            out.content.contains("calls helper -> a.rs"),
            "{}",
            out.content
        );
        assert!(out.content.contains("suggested reads:"), "{}", out.content);
    }

    #[tokio::test]
    async fn context_pack_query_fallback_omits_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "README.md", "needle phrase secret words\n");
        write(tmp.path(), "src/lib.rs", "pub fn known() {}\n");
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(serde_json::json!({ "target": "needle phrase" }), &ctx)
            .await
            .unwrap();

        assert!(
            out.content.contains("context_pack: query"),
            "{}",
            out.content
        );
        assert!(out.content.contains("README.md:1"), "{}", out.content);
        assert!(out.content.contains("content omitted"), "{}", out.content);
        assert!(
            !out.content.contains("secret words"),
            "query packet must not print source line contents: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn context_pack_empty_repo_reports_diagnostic() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("no indexed files"), "{}", out.content);
        assert!(out.content.contains("project_root:"), "{}", out.content);
        assert!(out.content.contains("hint:"), "{}", out.content);
    }

    #[tokio::test]
    async fn context_pack_limit_reports_omitted_rows() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "many.rs",
            "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
        );
        let ctx = test_ctx(tmp.path());

        let out = ContextPackTool
            .call(
                serde_json::json!({ "target": "many.rs", "kind": "path", "limit": 1 }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(out.content.contains("one"), "{}", out.content);
        assert!(
            out.content.contains("more symbols omitted"),
            "{}",
            out.content
        );
    }

    // ---- centrality ranking + impact (code-graph layer) ----------------

    /// Write a project `.cockpit/config.json` toggling centrality ranking.
    /// The layered resolver makes the project layer win over any home
    /// config, so these tool tests are deterministic on a dev machine.
    fn set_centrality(root: &Path, enabled: bool) {
        write(
            root,
            ".cockpit/config.json",
            &format!("{{\"intelCentralityRanking\":{enabled}}}"),
        );
    }

    /// Fixture: `core.rs` is heavily called (high centrality), `util.rs`
    /// barely. Both define `widget`, so `symbol_find("widget")` returns
    /// both and centrality decides the order. `anchor` is unique to
    /// `core.rs` and called many times to lift its score.
    fn write_centrality_fixture(root: &Path) {
        write(root, "core.rs", "pub fn widget() {}\npub fn anchor() {}\n");
        write(root, "util.rs", "pub fn widget() {}\n");
        // A caller that invokes `anchor` (→ core.rs) many times.
        let mut body = String::from("pub fn driver() {\n");
        for _ in 0..10 {
            body.push_str("    anchor();\n");
        }
        body.push_str("}\n");
        write(root, "callers.rs", &body);
    }

    #[tokio::test]
    async fn symbol_find_ranks_central_file_first_and_reverts_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        write_centrality_fixture(tmp.path());

        // Ranking ON: the heavily-called `core.rs` definition ranks above
        // the rarely-called `util.rs` one.
        set_centrality(tmp.path(), true);
        let ctx = test_ctx(tmp.path());
        let out = SymbolFindTool
            .call(serde_json::json!({ "name": "widget", "exact": true }), &ctx)
            .await
            .unwrap();
        let core_at = out.content.find("core.rs").expect("core.rs present");
        let util_at = out.content.find("util.rs").expect("util.rs present");
        assert!(
            core_at < util_at,
            "central core.rs must rank first when ranking is on; got:\n{}",
            out.content
        );

        // Ranking OFF: revert to exact (path, line) alphabetical order, so
        // `core.rs` still precedes `util.rs` alphabetically — pick a name
        // where disabling flips the order to prove the switch bites.
        set_centrality(tmp.path(), false);
        let ctx2 = test_ctx(tmp.path());
        let off = SymbolFindTool
            .call(
                serde_json::json!({ "name": "widget", "exact": true }),
                &ctx2,
            )
            .await
            .unwrap();
        // Same SET of results regardless of switch (additive — recall
        // unchanged).
        assert!(off.content.contains("core.rs"));
        assert!(off.content.contains("util.rs"));
    }

    /// A name where the central file sorts LAST alphabetically, so ranking
    /// must reorder it to the front — and disabling must flip it back to
    /// alphabetical. Proves the switch genuinely changes order.
    #[tokio::test]
    async fn symbol_find_ranking_flips_order_vs_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        // `zcore.rs` (sorts last) is heavily called; `acold.rs` (sorts
        // first) is not. Both define `gadget`.
        write(
            tmp.path(),
            "zcore.rs",
            "pub fn gadget() {}\npub fn beacon() {}\n",
        );
        write(tmp.path(), "acold.rs", "pub fn gadget() {}\n");
        let mut body = String::from("pub fn run() {\n");
        for _ in 0..10 {
            body.push_str("    beacon();\n");
        }
        body.push_str("}\n");
        write(tmp.path(), "callers.rs", &body);

        // ON: central `zcore.rs` ranked first despite sorting last.
        set_centrality(tmp.path(), true);
        let ctx = test_ctx(tmp.path());
        let on = SymbolFindTool
            .call(serde_json::json!({ "name": "gadget", "exact": true }), &ctx)
            .await
            .unwrap();
        assert!(
            on.content.find("zcore.rs").unwrap() < on.content.find("acold.rs").unwrap(),
            "ranking must lift central zcore.rs above acold.rs; got:\n{}",
            on.content
        );

        // OFF: alphabetical → `acold.rs` first.
        set_centrality(tmp.path(), false);
        let ctx2 = test_ctx(tmp.path());
        let off = SymbolFindTool
            .call(
                serde_json::json!({ "name": "gadget", "exact": true }),
                &ctx2,
            )
            .await
            .unwrap();
        assert!(
            off.content.find("acold.rs").unwrap() < off.content.find("zcore.rs").unwrap(),
            "disabled must revert to alphabetical (acold.rs first); got:\n{}",
            off.content
        );
    }

    #[tokio::test]
    async fn search_ranks_central_file_first_and_is_additive() {
        let tmp = tempfile::tempdir().unwrap();
        // Both files contain the search term `gadget`; `zcore.rs` is
        // central (sorts last alphabetically), `acold.rs` is not.
        write(tmp.path(), "zcore.rs", "// gadget\npub fn beacon() {}\n");
        write(tmp.path(), "acold.rs", "// gadget\n");
        let mut body = String::from("pub fn run() {\n");
        for _ in 0..10 {
            body.push_str("    beacon();\n");
        }
        body.push_str("}\n");
        write(tmp.path(), "callers.rs", &body);

        // ON: central zcore.rs's match emitted before acold.rs's.
        set_centrality(tmp.path(), true);
        let ctx = test_ctx(tmp.path());
        let on = SearchTool
            .call(serde_json::json!({ "pattern": "gadget" }), &ctx)
            .await
            .unwrap();
        let on_lines: Vec<&str> = on
            .content
            .lines()
            .filter(|l| l.contains("gadget"))
            .collect();
        assert!(
            on_lines.iter().position(|l| l.contains("zcore.rs"))
                < on_lines.iter().position(|l| l.contains("acold.rs")),
            "central zcore.rs match must come first; got:\n{}",
            on.content
        );

        // OFF: file order (alphabetical from rg) → acold.rs first.
        set_centrality(tmp.path(), false);
        let ctx2 = test_ctx(tmp.path());
        let off = SearchTool
            .call(serde_json::json!({ "pattern": "gadget" }), &ctx2)
            .await
            .unwrap();

        // Additive: the SET of matched files is identical on vs off.
        let files_of = |s: &str| -> std::collections::BTreeSet<String> {
            s.lines()
                .filter(|l| l.contains("gadget"))
                .filter_map(|l| l.split_once(':').map(|(p, _)| p.to_string()))
                .collect()
        };
        assert_eq!(
            files_of(&on.content),
            files_of(&off.content),
            "ranking must be additive — same set of matches, only order differs"
        );
    }

    #[tokio::test]
    async fn impact_reports_caller_to_callee_in_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        // `helper` is defined once and called from `driver`'s body.
        write(
            tmp.path(),
            "lib.rs",
            "pub fn helper() {}\npub fn driver() {\n    helper();\n}\n",
        );
        let ctx = test_ctx(tmp.path());

        // Direction 1: callers of `helper` includes `driver`.
        let callers = ImpactTool
            .call(serde_json::json!({ "name": "helper" }), &ctx)
            .await
            .unwrap();
        assert!(
            callers.content.contains("Callers"),
            "got:\n{}",
            callers.content
        );
        assert!(
            callers.content.contains("lib.rs") && callers.content.contains("driver"),
            "helper's callers must list driver at lib.rs; got:\n{}",
            callers.content
        );

        // Direction 2: calls inside `driver` include `helper -> lib.rs`.
        let calls = ImpactTool
            .call(serde_json::json!({ "name": "driver" }), &ctx)
            .await
            .unwrap();
        assert!(calls.content.contains("Calls"), "got:\n{}", calls.content);
        assert!(
            calls.content.contains("helper -> lib.rs"),
            "driver's calls must resolve helper to lib.rs; got:\n{}",
            calls.content
        );
    }

    #[tokio::test]
    async fn impact_omits_ambiguous_callee() {
        let tmp = tempfile::tempdir().unwrap();
        // `dup` is defined in TWO files → ambiguous → high-precision omit.
        write(tmp.path(), "a.rs", "pub fn dup() {}\n");
        write(tmp.path(), "b.rs", "pub fn dup() {}\n");
        write(tmp.path(), "c.rs", "pub fn caller() {\n    dup();\n}\n");
        let ctx = test_ctx(tmp.path());

        // `caller`'s outgoing call to `dup` resolves to 2 defs → omitted.
        let calls = ImpactTool
            .call(serde_json::json!({ "name": "caller" }), &ctx)
            .await
            .unwrap();
        assert!(
            calls.content.contains("Calls: none"),
            "ambiguous callee must be omitted (no guessed edge); got:\n{}",
            calls.content
        );

        // And `dup` reports no callers (the edge is ambiguous either way).
        let callers = ImpactTool
            .call(serde_json::json!({ "name": "dup", "path": "a.rs" }), &ctx)
            .await
            .unwrap();
        assert!(
            callers.content.contains("Callers: none"),
            "ambiguous edge must not be asserted as a caller; got:\n{}",
            callers.content
        );
    }

    #[tokio::test]
    async fn impact_filters_ubiquitous_name() {
        let tmp = tempfile::tempdir().unwrap();
        // `get` is on the denylist — even a unique def + call is filtered.
        write(
            tmp.path(),
            "lib.rs",
            "pub fn get() {}\npub fn user() {\n    get();\n}\n",
        );
        let ctx = test_ctx(tmp.path());

        let calls = ImpactTool
            .call(serde_json::json!({ "name": "user" }), &ctx)
            .await
            .unwrap();
        assert!(
            calls.content.contains("Calls: none"),
            "denylisted `get` must be filtered from edges; got:\n{}",
            calls.content
        );
        let callers = ImpactTool
            .call(serde_json::json!({ "name": "get" }), &ctx)
            .await
            .unwrap();
        assert!(
            callers.content.contains("Callers: none"),
            "denylisted `get` must report no callers; got:\n{}",
            callers.content
        );
    }

    #[tokio::test]
    async fn impact_renders_empty_sections_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        // `lonely` has no callers and an empty body (no calls).
        write(tmp.path(), "lib.rs", "pub fn lonely() {}\n");
        let ctx = test_ctx(tmp.path());
        let out = ImpactTool
            .call(serde_json::json!({ "name": "lonely" }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("Callers: none"),
            "got:\n{}",
            out.content
        );
        assert!(out.content.contains("Calls: none"), "got:\n{}", out.content);
    }

    #[tokio::test]
    async fn impact_unknown_symbol_reports_no_match() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "lib.rs", "pub fn known() {}\n");
        let ctx = test_ctx(tmp.path());
        let out = ImpactTool
            .call(serde_json::json!({ "name": "nope" }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("No symbol matches"),
            "got:\n{}",
            out.content
        );
    }

    fn git(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn git_commit(root: &Path, message: &str) {
        let status = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Cockpit Test",
                "-c",
                "user.email=cockpit@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                message,
            ])
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git commit failed");
    }

    fn init_git(root: &Path) {
        git(root, &["init", "-q"]);
        git(root, &["add", "."]);
        git_commit(root, "init");
    }

    #[tokio::test]
    async fn change_impact_worktree_diff_maps_changed_function() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "lib.rs",
            "pub fn helper() {\n    let value = 1;\n}\n",
        );
        init_git(tmp.path());
        write(
            tmp.path(),
            "lib.rs",
            "pub fn helper() {\n    let value = 2;\n}\n",
        );
        let ctx = test_ctx(tmp.path());
        let out = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("M lib.rs"), "{}", out.content);
        assert!(out.content.contains("helper"), "{}", out.content);
        assert!(out.content.contains("symbols:"), "{}", out.content);
    }

    #[tokio::test]
    async fn change_impact_includes_caller_context_and_high_risk() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "lib.rs",
            "pub fn helper() {\n    let value = 1;\n}\npub fn driver() {\n    helper();\n}\n",
        );
        init_git(tmp.path());
        write(
            tmp.path(),
            "lib.rs",
            "pub fn helper() {\n    let value = 2;\n}\npub fn driver() {\n    helper();\n}\n",
        );
        let ctx = test_ctx(tmp.path());
        let out = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("risk=high"), "{}", out.content);
        assert!(out.content.contains("caller lib.rs"), "{}", out.content);
        assert!(out.content.contains("driver"), "{}", out.content);
    }

    #[tokio::test]
    async fn change_impact_reports_added_deleted_and_renamed_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "deleted.rs", "pub fn removed() {}\n");
        write(tmp.path(), "old.rs", "pub fn moved() {}\n");
        init_git(tmp.path());
        write(tmp.path(), "added.rs", "pub fn added() {}\n");
        std::fs::remove_file(tmp.path().join("deleted.rs")).unwrap();
        git(tmp.path(), &["mv", "old.rs", "new.rs"]);
        let ctx = test_ctx(tmp.path());
        let out = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("A added.rs"), "{}", out.content);
        assert!(out.content.contains("D deleted.rs"), "{}", out.content);
        assert!(out.content.contains("R new.rs"), "{}", out.content);
        assert!(out.content.contains("from old.rs"), "{}", out.content);
    }

    #[tokio::test]
    async fn change_impact_invalid_ref_returns_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "lib.rs", "pub fn known() {}\n");
        init_git(tmp.path());
        let ctx = test_ctx(tmp.path());
        let err = ChangeImpactTool
            .call(serde_json::json!({ "base": "definitely-not-a-ref" }), &ctx)
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("invalid git diff request"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn change_impact_non_git_directory_reports_diagnostic() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "lib.rs", "pub fn known() {}\n");
        let ctx = test_ctx(tmp.path());
        let out = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("no git worktree"), "{}", out.content);
    }

    #[tokio::test]
    async fn change_impact_path_filter_limits_changed_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "src/a.rs",
            "pub fn a() {\n    let value = 1;\n}\n",
        );
        write(
            tmp.path(),
            "tests/b.rs",
            "pub fn b() {\n    let value = 1;\n}\n",
        );
        init_git(tmp.path());
        write(
            tmp.path(),
            "src/a.rs",
            "pub fn a() {\n    let value = 2;\n}\n",
        );
        write(
            tmp.path(),
            "tests/b.rs",
            "pub fn b() {\n    let value = 2;\n}\n",
        );
        let ctx = test_ctx(tmp.path());
        let out = ChangeImpactTool
            .call(serde_json::json!({ "path": "src" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("M src/a.rs"), "{}", out.content);
        assert!(!out.content.contains("tests/b.rs"), "{}", out.content);
    }

    #[tokio::test]
    async fn change_impact_risk_tiers_are_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "leaf.rs",
            "pub fn leaf() {\n    let value = 1;\n}\n",
        );
        write(
            tmp.path(),
            "called.rs",
            "pub fn called() {\n    let value = 1;\n}\npub fn user() {\n    called();\n}\n",
        );
        init_git(tmp.path());
        write(
            tmp.path(),
            "leaf.rs",
            "pub fn leaf() {\n    let value = 2;\n}\n",
        );
        write(
            tmp.path(),
            "called.rs",
            "pub fn called() {\n    let value = 2;\n}\npub fn user() {\n    called();\n}\n",
        );
        let ctx = test_ctx(tmp.path());
        let first = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .content;
        let second = ChangeImpactTool
            .call(serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .content;
        assert_eq!(first, second);
        assert!(first.contains("called.rs risk=high"), "{}", first);
        assert!(first.contains("leaf.rs risk=medium"), "{}", first);
    }
}
