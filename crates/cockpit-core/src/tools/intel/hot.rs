use super::common::*;

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
    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
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
            .hidden(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .parents(true)
            .require_git(false)
            .follow_links(false)
            .filter_entry(crate::tools::text_search::is_not_dot_git_dir);
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
            if !write_retained_line(&mut writer, &format!("{rel}  {size}b")) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated; lower `limit`]\n"))
    }
}
