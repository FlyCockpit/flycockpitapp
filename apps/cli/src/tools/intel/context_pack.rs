use super::common::*;
use crate::tools::text_search::{SearchOptions, search_records_blocking};

// ---- context_pack ----------------------------------------------------------

pub struct ContextPackTool;

#[derive(Debug, Deserialize)]
struct ContextPackArgs {
    target: Option<String>,
    kind: Option<String>,
    depth: Option<u64>,
    limit: Option<u64>,
}

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
    lines: Option<usize>,
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
        let args: ContextPackArgs = typed_args(args)?;
        let target = args
            .target
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let requested = parse_context_pack_kind(args.kind.as_deref())?;
        let depth = args.depth.map(|d| d.clamp(1, 3) as usize).unwrap_or(1);
        let limit = args.limit.map(|l| l.clamp(1, 50) as usize).unwrap_or(12);

        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let file_rows = index.context_file_rows()?;
        let fs_files = list_file_metas(&ctx.session.project_root);
        if file_rows.is_empty() && fs_files.is_empty() {
            return Ok(ToolOutput::text(format!(
                "context_pack: no indexed files\nproject_root: {}\ncwd: {}\nhint: verify the project root/cwd; try `context_pack` again after files exist, or use `tree`/`rg --files` to diagnose discovery.",
                ctx.session.project_root.display(),
                ctx.cwd.display()
            )));
        }

        let centrality = index.centrality_scores()?;
        let files = context_file_meta(&file_rows, &fs_files, &centrality);
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
                context_pack_query(&index, &files, target, ctx, limit).await
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
    indexed_rows: &[FileMetaRow],
    fs_files: &[FsFileMeta],
    centrality: &HashMap<String, f64>,
) -> Vec<ContextFileMeta> {
    let indexed_paths: HashSet<&str> = indexed_rows.iter().map(|row| row.path.as_str()).collect();
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
    for row in indexed_rows {
        metas.push(ContextFileMeta {
            path: row.path.clone(),
            language: row.language.clone(),
            size: row.size.max(0) as u64,
            lines: row.lines.map(|n| n.max(0) as usize),
            symbols: row.symbols,
            mtime: system_time_from_ns(row.mtime_ns),
            centrality: centrality.get(&row.path).copied().unwrap_or(0.0),
            centrality_rank: ranks.get(row.path.as_str()).copied(),
        });
    }

    for file in fs_files {
        if indexed_paths.contains(file.rel.as_str()) {
            continue;
        }
        metas.push(ContextFileMeta {
            path: file.rel.clone(),
            language: Language::from_path(Path::new(&file.rel))
                .as_str()
                .to_string(),
            size: file.size,
            lines: Some(0),
            symbols: 0,
            mtime: file.mtime,
            centrality: centrality.get(&file.rel).copied().unwrap_or(0.0),
            centrality_rank: ranks.get(file.rel.as_str()).copied(),
        });
    }
    metas.sort_by(|a, b| a.path.cmp(&b.path));
    metas
}

fn line_count_label(lines: Option<usize>) -> String {
    lines
        .map(|value| format!("{value}L"))
        .unwrap_or_else(|| "[large]".to_string())
}

fn line_count_value(lines: Option<usize>) -> String {
    lines
        .map(|value| value.to_string())
        .unwrap_or_else(|| "[large]".to_string())
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
        if !writer.writeln(&format!(
            "  {}  {}b {}",
            file.path,
            file.size,
            line_count_label(file.lines)
        )) {
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
                "  {} {} symbols={} {}",
                file.path,
                file.language,
                file.symbols,
                line_count_label(file.lines)
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

    let dep_edges = index.dep_edges()?;
    let cycles = import_cycles(&dep_edges);
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
        line_count_value(file.lines),
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

async fn context_pack_query(
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
    let text_hits = in_process_text_hits(target, ctx, limit.saturating_mul(2)).await?;
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

fn import_cycles(edges: &[DepEdge]) -> Vec<Vec<String>> {
    let mut nodes: Vec<String> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    let mut adj: Vec<Vec<usize>> = Vec::new();
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    for edge in edges {
        if let Some(importee) = edge.importee.as_deref() {
            let a = intern(&edge.importer, &mut nodes, &mut idx, &mut adj);
            let b = intern(importee, &mut nodes, &mut idx, &mut adj);
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

fn system_time_secs(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn system_time_from_ns(ns: i64) -> Option<std::time::SystemTime> {
    let ns = u64::try_from(ns).ok()?;
    let secs = ns / 1_000_000_000;
    let nanos = (ns % 1_000_000_000) as u32;
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}

fn is_identifierish(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

async fn in_process_text_hits(
    target: &str,
    ctx: &ToolCtx,
    max_hits: usize,
) -> Result<Vec<(String, u64)>> {
    if max_hits == 0 {
        return Ok(Vec::new());
    }
    let search_root = crate::tools::sandbox::check_native_access(
        ctx,
        &ctx.session.project_root,
        crate::tools::shell_sandbox::SandboxPathAccess::Read,
    )
    .await?;
    let display_root = search_root.clone();
    let guard_root = search_root.clone();
    let options = SearchOptions {
        pattern: regex::escape(target),
        case_insensitive: false,
        columns: false,
        context: None,
        glob: None,
        max_matches: max_hits,
        hidden: true,
        parents: true,
    };
    let outcome = tokio::task::spawn_blocking(move || {
        search_records_blocking(&search_root, &display_root, &options, |path| {
            path == guard_root || path.starts_with(&guard_root)
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("context_pack search worker joined: {e}"))??;
    Ok(outcome
        .records
        .into_iter()
        .filter(|record| !record.is_context)
        .take(max_hits)
        .map(|record| (record.path, record.line_number))
        .collect())
}
