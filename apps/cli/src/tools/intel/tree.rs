use super::common::*;

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
        let indexed: HashMap<String, (String, i64, Option<i64>, i64)> = index
            .tree_rows()?
            .into_iter()
            .map(|(p, lang, size, lines, syms)| (p, (lang, size, lines, syms)))
            .collect();

        // The on-disk gitignore walk is the authority for which files
        // exist (it sees unknown-language files the index doesn't store).
        let mut entries = match filter.as_deref() {
            Some(subdir) => list_files_under(&ctx.session.project_root, subdir),
            None => list_files(&ctx.session.project_root),
        };
        entries.sort();

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for (rel, _abs, size) in &entries {
            let lang = Language::from_path(Path::new(rel));
            let line = match indexed.get(rel) {
                Some((lang_str, _indexed_size, Some(lines), syms)) => {
                    format!("{rel}  {lang_str} {size}b {lines}L [{syms} sym]")
                }
                Some((lang_str, _indexed_size, None, syms)) => {
                    format!("{rel}  {lang_str} {size}b [large] [{syms} sym]")
                }
                None => format!("{rel}  {} {size}b [not indexed]", lang.as_str()),
            };
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
    if filter.is_some() {
        out.push_str("empty_reason: `path` filter excluded all discovered files\n");
        out.push_str("hint: run `tree` without `path` or use a different subtree.");
    } else if fs_files == 0 {
        out.push_str("empty_reason: zero discovered files\n");
        out.push_str(
            "hint: verify the project root/cwd; fall back to `rg --files` or `fd` if the filesystem walk is unexpectedly empty.",
        );
    } else {
        out.push_str("empty_reason: no output rows after discovery\n");
        out.push_str(
            "hint: verify the project root/cwd; fall back to `rg --files` or `fd` if the filesystem walk is unexpectedly empty.",
        );
    }
    out
}
