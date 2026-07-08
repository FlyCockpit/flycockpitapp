//! `grep` — sandboxed regex content search (prompt `docs-agent.md`
//! components B + decision 2). Assigned **only** to the `docs` answerer
//! (Docs.2).
//!
//! Implemented with the ripgrep library crates (`grep-regex` +
//! `grep-searcher`), never by shelling out to `rg` — shelling would
//! defeat the sandbox the whole `docs` design rests on. Every file
//! searched is confined to the tool's cwd root via
//! [`crate::tools::sandbox`]; output is budgeted (whole `file:line`
//! records dropped atomically under a token cap) via
//! [`crate::intel::budget::BudgetedWriter`].

use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use grep_regex::RegexMatcher;
use grep_searcher::sinks::UTF8;
use grep_searcher::{BinaryDetection, SearcherBuilder};
use ignore::WalkBuilder;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::intel::budget::BudgetedWriter;
use crate::intel::thin::{ThinLimits, thin_line_output};
use crate::tools::sandbox;

/// cl100k token cap for one `grep` result (subagent-report economy,
/// GOALS §10). Generous enough for a focused dependency query, tight
/// enough that a runaway pattern can't flood the context.
const GREP_TOKEN_CAP: usize = 4_000;

/// Hard cap on matches collected before we stop walking — bounds work on
/// huge dependencies even before the token budget bites.
const MAX_MATCHES: usize = 2_000;

pub struct GrepTool;

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "grep"
    }

    fn description(&self) -> &str {
        "Regex content search confined to the package root; returns budgeted file:line matches"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Search file contents for a regular expression within this package's source tree and \
             get back budgeted file:line matches. You have no shell here, so this is how you find \
             code: use it to locate where a symbol, string, or pattern appears in the dependency \
             you're inspecting. The search is hard-confined to the package root — you cannot \
             reach outside it. Narrow with `path` to one subdirectory or file when you can, and \
             then `read` the interesting matches for context."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern":          { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "Regex to search for" },
                "path":             { "type": "string", "x-cockpit-kind": "path", "description": "`path` subdirectory or file under the root (default: whole root)" },
                "case_insensitive": { "type": "boolean", "description": "Case-insensitive match (default false)" }
            },
            "required": ["pattern"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern":          { "type": "string", "x-cockpit-aliases": ["query", "regex", "search", "q", "expression"], "description": "The regular expression to search file contents for" },
                "path":             { "type": "string", "x-cockpit-kind": "path", "description": "Optional `path` subdirectory or file under the package root to restrict the search to; omit to search the whole package. Cannot point outside the root" },
                "case_insensitive": { "type": "boolean", "description": "When true, match case-insensitively; defaults to case-sensitive" }
            },
            "required": ["pattern"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let pattern = args
            .get("pattern")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`pattern` is required"))?
            .to_string();
        let case_insensitive = args
            .get("case_insensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Resolve + confine the search root. A `path` arg narrows the
        // search; absence searches the whole package root.
        let canonical_root = sandbox::canonical_root(&ctx.cwd)?;
        let search_root = match args.get("path").and_then(Value::as_str) {
            Some(p) if !p.is_empty() => sandbox::confine(&ctx.cwd, p)?,
            _ => canonical_root.clone(),
        };

        // Case folding rides as an inline `(?i)` flag so the parameter
        // surface stays terse (one bool, no builder knobs exposed).
        let effective = if case_insensitive {
            format!("(?i){pattern}")
        } else {
            pattern.clone()
        };
        let matcher = RegexMatcher::new_line_matcher(&effective).map_err(|e| {
            invalid_input(format!(
                "invalid regex `{pattern}` ({e}); check for unescaped backslashes or unbalanced brackets"
            ))
        })?;

        let root = canonical_root.clone();
        let query = pattern.clone();
        let out = tokio::task::spawn_blocking(move || {
            search_blocking(&matcher, &search_root, &root, &query)
        })
        .await
        .map_err(|e| anyhow::anyhow!("grep worker joined: {e}"))??;

        Ok(out)
    }
}

/// Run the search on a blocking thread (the ripgrep API is sync I/O).
fn search_blocking(
    matcher: &RegexMatcher,
    search_root: &Path,
    canonical_root: &Path,
    query: &str,
) -> Result<ToolOutput> {
    let mut match_count = 0usize;
    let mut hit_match_cap = false;
    let mut records = Vec::new();

    // Gitignore-aware walk confined to the search root. `require_git
    // (false)` so a dependency clone without a checked-in `.gitignore`
    // still walks; symlinks are NOT followed (escape guard).
    let walk = WalkBuilder::new(search_root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .build();

    'walk: for entry in walk.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        // Defense in depth: re-verify each entry stays within the root
        // (symlinked dir entries, races).
        if !sandbox::within_root(canonical_root, path) {
            continue;
        }
        // Relative display path for citations.
        let rel = path
            .strip_prefix(canonical_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        let mut searcher = SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(0))
            .line_number(true)
            .build();

        let mut file_matches: Vec<(u64, String)> = Vec::new();
        let sink = UTF8(|line_number, line| {
            file_matches.push((line_number, line.trim_end().to_string()));
            Ok(true)
        });
        // A search error on one file (binary, permission) is skipped, not
        // fatal — the sandbox must answer best-effort.
        if searcher.search_path(matcher, path, sink).is_err() {
            continue;
        }

        for (line_number, line) in file_matches {
            let record = format!("{rel}:{line_number}: {}", line.trim());
            records.push(record);
            match_count += 1;
            if match_count >= MAX_MATCHES {
                hit_match_cap = true;
                break 'walk;
            }
        }
    }

    if records.is_empty() {
        return Ok(ToolOutput::text("No matches.".to_string()));
    }

    let raw = records.join("\n") + "\n";
    let (body, thinned) = thin_line_output(&raw, query, ThinLimits::default());
    let mut writer = BudgetedWriter::new(GREP_TOKEN_CAP);
    for line in body.lines() {
        if !writer.writeln(line) {
            break;
        }
    }
    let writer_truncated = writer.is_truncated();
    let truncated = writer_truncated || hit_match_cap || thinned;
    let mut body = writer.into_string();
    if truncated {
        if writer_truncated || hit_match_cap {
            body.push_str("... [truncated; narrow the pattern or pass a `path`]\n");
        }
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
    async fn finds_matches_with_file_line() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/lib.rs", "fn alpha() {}\nfn beta() {}\n");
        write(tmp.path(), "README.md", "alpha docs\n");
        let ctx = test_ctx(tmp.path());
        let out = GrepTool
            .call(serde_json::json!({ "pattern": "alpha" }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("src/lib.rs:1:"),
            "got: {}",
            out.content
        );
        assert!(out.content.contains("README.md:1:"), "got: {}", out.content);
    }

    #[tokio::test]
    async fn case_insensitive_flag() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "f.rs", "HELLO world\n");
        let ctx = test_ctx(tmp.path());
        let sensitive = GrepTool
            .call(serde_json::json!({ "pattern": "hello" }), &ctx)
            .await
            .unwrap();
        assert!(sensitive.content.contains("No matches"));
        let insensitive = GrepTool
            .call(
                serde_json::json!({ "pattern": "hello", "case_insensitive": true }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(insensitive.content.contains("f.rs:1:"));
    }

    #[tokio::test]
    async fn refuses_path_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("pkg");
        std::fs::create_dir_all(&root).unwrap();
        write(tmp.path(), "secret.txt", "credentials\n");
        write(&root, "inside.rs", "ok\n");
        let ctx = test_ctx(&root);
        // Attempt to search a parent dir via `..` — must be refused.
        let out = GrepTool
            .call(
                serde_json::json!({ "pattern": "credentials", "path": "../" }),
                &ctx,
            )
            .await;
        assert!(out.is_err(), "path-escape must be refused");
    }

    #[tokio::test]
    async fn thins_large_result_sets_with_per_file_omission_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 1..=20 {
            if i == 10 {
                body.push_str("target panic failure\n");
            } else {
                body.push_str("target filler\n");
            }
        }
        write(tmp.path(), "src/lib.rs", &body);
        let ctx = test_ctx(tmp.path());
        let out = GrepTool
            .call(serde_json::json!({ "pattern": "target" }), &ctx)
            .await
            .unwrap();

        assert!(out.truncated, "thinning should mark the output truncated");
        assert!(
            out.content.contains("src/lib.rs:1:"),
            "got: {}",
            out.content
        );
        assert!(
            out.content.contains("src/lib.rs:20:"),
            "got: {}",
            out.content
        );
        assert!(
            out.content.contains("src/lib.rs:10: target panic failure"),
            "got: {}",
            out.content
        );
        assert!(
            out.content
                .contains("more matches in src/lib.rs omitted; narrow query or path"),
            "got: {}",
            out.content
        );
    }
}
