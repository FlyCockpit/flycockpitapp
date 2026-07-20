use super::common::*;
use crate::tools::text_search::{
    SearchOptions, SearchOutcome, normalize_display_root, search_records_blocking,
};

// ---- search ----------------------------------------------------------------

pub struct SearchTool;

const MAX_SEARCH_MATCHES: usize = 2_000;

#[async_trait]
impl Tool for SearchTool {
    fn name(&self) -> &str {
        "search"
    }
    fn description(&self) -> &str {
        "Budgeted repo-wide regex text search; use `grep` for root-confined regex, `word` for identifier uses, `symbol_find` for definitions"
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
        crate::tools::sandbox::check_native_access(
            ctx,
            &search_path,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
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
        let (search_root, display_root) = match &target {
            SearchTarget::Dir(dir) => (dir.clone(), dir.clone()),
            SearchTarget::File(file) => normalize_display_root(file),
        };
        let guard_root = search_root.clone();
        let options = SearchOptions {
            pattern: pattern.to_string(),
            case_insensitive: ignore_case,
            columns: true,
            context: context.map(|n| n as usize),
            glob: glob.map(ToString::to_string),
            max_matches: MAX_SEARCH_MATCHES,
            hidden: true,
            parents: true,
        };
        let outcome = tokio::task::spawn_blocking(move || {
            search_records_blocking(&search_root, &display_root, &options, |path| {
                path == guard_root || path.starts_with(&guard_root)
            })
        })
        .await
        .map_err(|e| anyhow::anyhow!("search worker joined: {e}"))??;
        let hit_match_cap = outcome.hit_match_cap;
        let body = format_search_records(&outcome);
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
            let scores = index.centrality_scores()?;
            rank_search_body(&body, &scores, path)
        } else {
            body
        };

        let (render_body, thinned) = thin_line_output(&ranked_body, pattern, ThinLimits::default());
        let mut writer = BudgetedWriter::new(SEARCH_TOKEN_CAP);
        for line in render_body.lines() {
            if !write_retained_line(&mut writer, line) {
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
                .with_truncated_retention(retained_truncated_body(&ranked_body))
        } else {
            finish(
                writer,
                "\n... [truncated; narrow the query or add a `path`/`glob` filter]\n",
            )
        };
        if hit_match_cap {
            out.truncated = true;
            out.content
                .push_str("... [truncated; narrow the query or add a `path`/`glob` filter]\n");
        }
        if single_file {
            out.content.push_str(SINGLE_FILE_NOTE);
        }
        Ok(out)
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
    let mut order: Vec<&str> = Vec::new();
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current: Option<&str> = None;
    for line in body.lines() {
        let file = line.split_once(':').map(|(p, _)| p);
        let key = match file {
            Some(f) => {
                if !groups.contains_key(f) {
                    order.push(f);
                }
                current = Some(f);
                f
            }
            // A line with no `:` (rare) attaches to the current group, or
            // starts a degenerate group keyed by itself.
            None => match current {
                Some(c) => c,
                None => {
                    if !groups.contains_key(line) {
                        order.push(line);
                    }
                    current = Some(line);
                    line
                }
            },
        };
        groups.entry(key).or_default().push(line);
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

fn format_search_records(outcome: &SearchOutcome) -> String {
    let mut out = String::new();
    for record in &outcome.records {
        let sep = if record.is_context { '-' } else { ':' };
        match record.column {
            Some(column) => out.push_str(&format!(
                "{}:{}:{}{} {}\n",
                record.path, record.line_number, column, sep, record.text
            )),
            None => out.push_str(&format!(
                "{}:{}{} {}\n",
                record.path, record.line_number, sep, record.text
            )),
        }
    }
    out
}

// ---- shared FS helpers -----------------------------------------------------
