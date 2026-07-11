use super::common::*;

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
