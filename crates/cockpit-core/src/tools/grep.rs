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

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::intel::budget::BudgetedWriter;
use crate::intel::thin::{ThinLimits, thin_line_output};
use crate::tools::sandbox;
use crate::tools::text_search::{SearchOptions, SearchOutcome, search_records_blocking};

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

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
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

        let display_root = canonical_root.clone();
        let guard_root = canonical_root.clone();
        let query = pattern.clone();
        let options = SearchOptions {
            pattern,
            case_insensitive,
            columns: false,
            context: None,
            glob: None,
            max_matches: MAX_MATCHES,
            hidden: false,
            parents: false,
        };
        let out = tokio::task::spawn_blocking(move || {
            search_records_blocking(&search_root, &display_root, &options, |path| {
                sandbox::within_root(&guard_root, path)
            })
            .map(|outcome| render_search_outcome(outcome, &query))
        })
        .await
        .map_err(|e| anyhow::anyhow!("grep worker joined: {e}"))??;

        Ok(out)
    }
}

fn render_search_outcome(outcome: SearchOutcome, query: &str) -> ToolOutput {
    if outcome.records.is_empty() {
        return ToolOutput::text("No matches.".to_string());
    }

    let raw = outcome
        .records
        .iter()
        .map(|record| {
            format!(
                "{}:{}: {}",
                record.path,
                record.line_number,
                record.text.trim()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let (body, thinned) = thin_line_output(&raw, query, ThinLimits::default());
    let mut writer = BudgetedWriter::new(GREP_TOKEN_CAP);
    for line in body.lines() {
        if !writer.writeln(line) {
            break;
        }
    }
    let writer_truncated = writer.is_truncated();
    let truncated = writer_truncated || outcome.hit_match_cap || thinned;
    let mut body = writer.into_string();
    if truncated {
        if writer_truncated || outcome.hit_match_cap {
            body.push_str("... [truncated; narrow the pattern or pass a `path`]\n");
        }
        ToolOutput::truncated_text(body)
    } else {
        ToolOutput::text(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::common::test_ctx;
    use std::path::Path;

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
