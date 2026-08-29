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
        "Budgeted repo-wide regex text search; use `grep` for root-confined regex, `code` for identifiers/definitions, and `context_pack` for orientation bundles"
    }
    fn verbose_description(&self) -> Option<String> {
        Some(
            "When you would reach for `rg`/`grep` in `bash`, call `search` instead — same ripgrep \
             power, but budget-capped so it won't flood your context. It returns `file:line` \
             matches for a regular expression. Use it for any text/pattern/comment/string. \
             Narrow with `path`/`glob`, add `context` for surrounding lines. For one specific \
             identifier, `code {kind:\"symbol_find\"}` finds where it is DEFINED and \
             `code {kind:\"word\"}` finds every USE."
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
                "case_insensitive": { "type": "boolean", "description": "Case-insensitive match toggle" },
                "context":          { "type": "integer", "description": "Context lines around each match" },
                "glob":             { "type": "string", "description": "`glob` include filter (e.g. `*.rs`)" }
            },
            "required": ["pattern"]
        })
    }
    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern":          { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "The regular expression to search for across file contents" },
                "path":             { "type": "string", "x-cockpit-kind": "path", "description": "Optional path to restrict the search to, relative to the project root; omit to search the whole repo" },
                "case_insensitive": { "type": "boolean", "description": "When true, match case-insensitively; defaults to case-sensitive" },
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
        let case_insensitive = args
            .get("case_insensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let context = args
            .get("context")
            .and_then(Value::as_u64)
            .map(|c| c.min(10));
        let glob = args.get("glob").and_then(Value::as_str);

        let root = intel_root(ctx).to_path_buf();
        let search_path = match path {
            Some(p) => crate::tools::common::resolve(p, &ctx.cwd),
            None => root.clone(),
        };
        // Native-tool boundary check (sandboxing part 2): one pre-scan check
        // gates the requested root/file before search reads any contents, so
        // an out-of-boundary tree stops at the first denial instead of
        // prompting per file.
        let search_path = crate::tools::sandbox::check_native_access(
            ctx,
            &search_path,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        // `metadata` is the first post-approval host access. Fence the exact
        // checked target before it can reveal or branch on filesystem state.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
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
        let (search_root, display_root, requested_file) = match &target {
            SearchTarget::Dir(dir) => (dir.clone(), dir.clone(), None),
            SearchTarget::File(file) => {
                let (root, display) = normalize_display_root(file);
                (root, display, Some(file.clone()))
            }
        };
        let guard_root = search_root.clone();
        if let Some(refusal) = crate::tools::sandbox::check_gitignore_read(
            ctx,
            requested_file.as_deref().unwrap_or(&guard_root),
        )
        .await?
        {
            return Ok(refusal);
        }

        // The gitignore gate can park while its own repository probes run.
        // Recheck the original requested access after that gate and directly
        // before the blocking walker reads the target tree.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            requested_file.as_deref().unwrap_or(&guard_root),
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;

        let options = SearchOptions {
            pattern: pattern.to_string(),
            case_insensitive,
            columns: true,
            context: context.map(|n| n as usize),
            glob: glob.map(ToString::to_string),
            max_matches: MAX_SEARCH_MATCHES,
            hidden: false,
            parents: true,
        };
        let secret_paths = ctx
            .session
            .secret_path_matcher(&ctx.config.extended().redact)
            .clone();
        let outcome = tokio::task::spawn_blocking(move || {
            search_records_blocking(&search_root, &display_root, &options, |path| {
                (path == guard_root || path.starts_with(&guard_root))
                    && requested_file.as_ref().is_none_or(|file| path == file)
                    && !secret_paths.is_secret_path(path)
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
            // Ranking is an optional presentation enhancement. Search remains
            // available when its best-effort index refresh cannot run.
            let index = index_of(ctx);
            match index
                .ensure_fresh_scoped(freshen_options(ctx, path.map(|p| rel_path(p, ctx))))
                .await
            {
                Ok(_) => match index.centrality_scores().await {
                    Ok(scores) => rank_search_body(&body, &scores, path),
                    Err(error) => {
                        tracing::debug!(%error, "skipping search centrality ranking");
                        body
                    }
                },
                Err(error) => {
                    tracing::debug!(%error, "skipping search centrality refresh");
                    body
                }
            }
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
                .with_text_artifact_capture(capture_text_artifact_body(&ranked_body))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn search_cannot_bypass_secret_path_gate() {
        let project = tempfile::tempdir().unwrap();
        let file = project.path().join(".env.production");
        std::fs::write(&file, "TOKEN=long-secret-value").unwrap();
        let mut ctx = crate::tools::common::test_ctx(project.path());
        ctx.approver = None;
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);
        let out = SearchTool
            .call(
                serde_json::json!({ "pattern": "(?s).", "path": file }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("secret-bearing"), "{out:?}");
        assert!(!out.content.contains("long-secret-value"), "{out:?}");
    }

    #[tokio::test]
    async fn intel_search_stops_at_first_denied_path() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "needle").unwrap();
        let mut ctx = crate::tools::common::test_ctx(project.path());
        ctx.approver = None;
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);

        let err = SearchTool
            .call(
                serde_json::json!({
                    "pattern": "needle",
                    "path": outside.path().to_string_lossy(),
                }),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("cannot be approved"),
            "search must stop at the native-access denial before scanning: {err}"
        );
    }
}

// ---- shared FS helpers -----------------------------------------------------
