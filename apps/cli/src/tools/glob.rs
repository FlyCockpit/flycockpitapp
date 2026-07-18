//! `glob` — sandboxed filename/path pattern listing (prompt
//! `docs-agent.md` components B + decision 2). Assigned **only** to the
//! `docs` answerer (Docs.2).
//!
//! Walks the package root gitignore-aware via the `ignore` crate
//! (already a cockpit dep), matches each relative path against a
//! `globset` pattern, and returns the matching paths budgeted under a
//! token cap. Every entry is confined to the cwd root via
//! [`crate::tools::sandbox`] — no `..`, no symlink escape.

use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use globset::{Glob, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::Deserialize;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input, typed_args};
use crate::intel::budget::BudgetedWriter;
use crate::tools::sandbox;

/// cl100k token cap for one `glob` listing (GOALS §10).
const GLOB_TOKEN_CAP: usize = 4_000;

/// Hard cap on entries collected before stopping the walk.
const MAX_ENTRIES: usize = 5_000;

pub struct GlobTool;

#[derive(Debug, Deserialize)]
struct GlobArgs {
    pattern: String,
    path: Option<String>,
}

#[async_trait]
impl Tool for GlobTool {
    fn name(&self) -> &str {
        "glob"
    }

    fn description(&self) -> &str {
        "List files matching a glob pattern within the package root, gitignore-aware"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "List the files in this package whose paths match a glob pattern, respecting \
             `.gitignore`. With no shell available, this is how you discover which files exist \
             and where — use it to find the entry points, modules, or file types of the \
             dependency you're inspecting before reading them. The walk is hard-confined to the \
             package root. Use patterns like `**/*.rs` (all Rust files at any depth) or `src/**` \
             (everything under `src`); scope the walk with `path` when you only care about a \
             subtree."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern": { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "Glob pattern, e.g. `**/*.rs` or `src/**`" },
                "path":    { "type": "string", "x-cockpit-kind": "path", "description": "`path` subdirectory under the root to scope the walk (default: whole root)" }
            },
            "required": ["pattern"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern": { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "The glob pattern to match file paths against, e.g. `**/*.rs` for all Rust files or `src/**` for everything under `src`" },
                "path":    { "type": "string", "x-cockpit-kind": "path", "description": "Optional `path` subdirectory under the package root to limit the walk to; omit to walk the whole package. Cannot point outside the root" }
            },
            "required": ["pattern"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: GlobArgs = typed_args(args)?;
        if args.pattern.trim().is_empty() {
            return Err(invalid_input("`pattern` is required"));
        }
        let pattern = args.pattern;

        let canonical_root = sandbox::canonical_root(&ctx.cwd)?;
        let walk_root = match args.path.as_deref() {
            Some(p) if !p.is_empty() => sandbox::confine(&ctx.cwd, p)?,
            _ => canonical_root.clone(),
        };

        let glob = Glob::new(&pattern)
            .map_err(|e| invalid_input(format!("invalid glob `{pattern}`: {e}")))?;
        let mut builder = GlobSetBuilder::new();
        builder.add(glob);
        let set = builder
            .build()
            .map_err(|e| invalid_input(format!("invalid glob `{pattern}`: {e}")))?;

        let root = canonical_root.clone();
        let out = tokio::task::spawn_blocking(move || glob_blocking(&set, &walk_root, &root))
            .await
            .map_err(|e| anyhow::anyhow!("glob worker joined: {e}"))??;
        Ok(out)
    }
}

fn glob_blocking(
    set: &globset::GlobSet,
    walk_root: &Path,
    canonical_root: &Path,
) -> Result<ToolOutput> {
    let mut writer = BudgetedWriter::new(GLOB_TOKEN_CAP);
    let mut count = 0usize;
    let mut hit_cap = false;

    let walk = WalkBuilder::new(walk_root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .build();

    for entry in walk.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if !sandbox::within_root(canonical_root, path) {
            continue;
        }
        let rel = path
            .strip_prefix(canonical_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if !set.is_match(&rel) {
            continue;
        }
        if !writer.writeln(&rel) {
            hit_cap = true;
            break;
        }
        count += 1;
        if count >= MAX_ENTRIES {
            hit_cap = true;
            break;
        }
    }

    if writer.is_empty() {
        return Ok(ToolOutput::text("No matching files.".to_string()));
    }
    let truncated = writer.is_truncated() || hit_cap;
    let mut body = writer.into_string();
    if truncated {
        body.push_str("... [truncated; narrow the pattern or pass a `path`]\n");
        Ok(ToolOutput::truncated_text(body))
    } else {
        Ok(ToolOutput::text(body))
    }
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
    async fn matches_glob_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/a.rs", "");
        write(tmp.path(), "src/b.rs", "");
        write(tmp.path(), "README.md", "");
        let ctx = test_ctx(tmp.path());
        let out = GlobTool
            .call(serde_json::json!({ "pattern": "**/*.rs" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("src/a.rs"));
        assert!(out.content.contains("src/b.rs"));
        assert!(!out.content.contains("README.md"));
    }

    #[tokio::test]
    async fn no_match_message() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "a.txt", "");
        let ctx = test_ctx(tmp.path());
        let out = GlobTool
            .call(serde_json::json!({ "pattern": "**/*.py" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("No matching files"));
    }

    #[tokio::test]
    async fn refuses_path_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("pkg");
        std::fs::create_dir_all(&root).unwrap();
        write(tmp.path(), "outside.rs", "");
        write(&root, "inside.rs", "");
        let ctx = test_ctx(&root);
        let out = GlobTool
            .call(serde_json::json!({ "pattern": "*.rs", "path": ".." }), &ctx)
            .await;
        assert!(out.is_err(), "path-escape must be refused");
    }
}
