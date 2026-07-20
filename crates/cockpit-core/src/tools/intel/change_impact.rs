use super::common::*;

// ---- change_impact ---------------------------------------------------------

pub struct ChangeImpactTool;

type HunkMap = HashMap<String, (Vec<(i64, i64)>, bool)>;
type DepAdjacency<'a> = HashMap<&'a str, Vec<&'a str>>;
type CallerRows = Vec<(String, i64, Option<String>)>;
type CallRows = Vec<(String, String, i64)>;

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
        "Summarize current diff/ref-range blast-radius hints; for one symbol's call graph, use `impact`"
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
        // Build import adjacency maps once; each changed file only runs BFS over these maps.
        let (forward_deps, reverse_deps) = dependency_adjacencies(&dep_edges);
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
        // Share expensive callgraph lookups across count, detail, and context passes.
        let mut callers_cache: HashMap<(String, i64), CallerRows> = HashMap::new();
        let mut calls_cache: HashMap<String, CallRows> = HashMap::new();
        for file in changed.iter().take(50) {
            let symbols = file_symbols.get(&file.path).cloned().unwrap_or_default();
            let overlapping = overlapping_symbols(&symbols, &file.ranges);
            let reverse = filtered_bfs(&reverse_deps, &file.path, depth, path_filter.as_deref());
            let forward = filtered_bfs(&forward_deps, &file.path, depth, path_filter.as_deref());
            let file_score = centrality.get(&file.path).copied().unwrap_or(0.0);
            let callers = overlapping
                .iter()
                .map(|s| memoized_impact_callers(&index, &mut callers_cache, &s.path, s.line).len())
                .sum::<usize>();
            let calls = overlapping
                .iter()
                .map(|s| memoized_impact_calls(&index, &mut calls_cache, &s.name).len())
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
            if !write_retained_line(
                &mut writer,
                &format!(
                    "  {} {} risk={}{}",
                    file.status,
                    file.path,
                    risk.as_str(),
                    suffix
                ),
            ) {
                return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
            }
            for symbol in overlapping {
                let sc = centrality.get(&symbol.path).copied().unwrap_or(0.0);
                let sym_callers =
                    memoized_impact_callers(&index, &mut callers_cache, &symbol.path, symbol.line);
                let sym_calls = memoized_impact_calls(&index, &mut calls_cache, &symbol.name);
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
                if !write_retained_line(
                    &mut writer,
                    &format!(
                        "  {}:{}-{} {} {} risk={} callers={} calls={}",
                        sym.path,
                        sym.line,
                        sym.end_line,
                        sym.kind,
                        sig,
                        risk.as_str(),
                        callers,
                        calls
                    ),
                ) {
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
            for (_dist, dep) in
                filtered_bfs(&reverse_deps, &file.path, depth, path_filter.as_deref())
                    .into_iter()
                    .take(40)
            {
                any_reverse = true;
                if !write_retained_line(&mut writer, &format!("  {} <- {}", file.path, dep)) {
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
            for (caller_file, caller_line, caller_symbol) in
                memoized_impact_callers(&index, &mut callers_cache, &sym.path, sym.line)
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
                if !write_retained_line(
                    &mut writer,
                    &format!(
                        "  caller {}:{}{} -> {}:{} {}",
                        caller_file, caller_line, in_sym, sym.path, sym.line, sym.name
                    ),
                ) {
                    return Ok(finish(writer, "\n... [truncated; narrow with `path`]\n"));
                }
            }
            for (callee, def_file, def_line) in
                memoized_impact_calls(&index, &mut calls_cache, &sym.name)
                    .into_iter()
                    .take(20)
            {
                if path_filter.as_deref().is_some_and(|p| {
                    !path_matches_filter(&def_file, p) && !changed_paths.contains(&sym.path)
                }) {
                    continue;
                }
                any_call = true;
                if !write_retained_line(
                    &mut writer,
                    &format!(
                        "  call {}:{} {} -> {}:{}",
                        sym.path, sym.line, callee, def_file, def_line
                    ),
                ) {
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

fn dependency_adjacencies(edges: &[DepEdge]) -> (DepAdjacency<'_>, DepAdjacency<'_>) {
    let mut forward: DepAdjacency<'_> = HashMap::new();
    let mut reverse: DepAdjacency<'_> = HashMap::new();
    for edge in edges {
        if let Some(importee) = &edge.importee {
            forward.entry(&edge.importer).or_default().push(importee);
            reverse.entry(importee).or_default().push(&edge.importer);
        }
    }
    (forward, reverse)
}

fn filtered_bfs(
    adj: &DepAdjacency<'_>,
    path: &str,
    depth: usize,
    filter: Option<&str>,
) -> Vec<(usize, String)> {
    bfs(adj, path, depth)
        .into_iter()
        .filter(|(_, p)| filter.is_none_or(|f| path_matches_filter(p, f)))
        .collect()
}

fn memoized_impact_callers(
    index: &Index,
    cache: &mut HashMap<(String, i64), CallerRows>,
    path: &str,
    line: i64,
) -> CallerRows {
    let key = (path.to_string(), line);
    if let Some(rows) = cache.get(&key) {
        return rows.clone();
    }
    let rows = index.impact_callers(path, line).unwrap_or_default();
    cache.insert(key, rows.clone());
    rows
}

fn memoized_impact_calls(
    index: &Index,
    cache: &mut HashMap<String, CallRows>,
    name: &str,
) -> CallRows {
    if let Some(rows) = cache.get(name) {
        return rows.clone();
    }
    let rows = index.impact_calls(name).unwrap_or_default();
    cache.insert(name.to_string(), rows.clone());
    rows
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
