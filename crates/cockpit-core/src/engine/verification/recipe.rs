//! Inherit and clean-room recipe assembly for ArtifactWrite verification.
//!
//! Clean-room guidance selection is target-anchored and trust-gated
//! (decision 11). Linked files are resolved against three bases, existence-
//! validated, contained under the workspace root, and capped.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;

use crate::agents::VerificationRecipe;
use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::engine::guidance_diff::unified_diff;
use crate::engine::message::Message;
use crate::session::Session;

const MAX_LINKED_FILES: usize = 8;
const MAX_LINKED_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRecipe {
    /// Stable-parts-first body (instructions + linked files) then volatile
    /// tail (recent reads + proposed diff). The stable prefix is intended to
    /// cache across verifications.
    pub prompt: String,
    pub stable_prefix: String,
    pub volatile_tail: String,
}

#[derive(Debug, Clone)]
pub struct RecipeAssemblyInput<'a> {
    pub recipe: &'a VerificationRecipe,
    pub history: &'a [Message],
    pub session: &'a Session,
    pub workspace_root: &'a Path,
    pub cwd: &'a Path,
    pub target_path: Option<&'a Path>,
    pub tool_name: &'a str,
    pub original_args: &'a Value,
    pub guidance_file_names: &'a [String],
    pub last_n_reads: u8,
    pub include_linked_files: bool,
    /// Framing prompt prepended to inherit recipes.
    pub inherit_framing: &'a str,
}

pub async fn assemble_recipe(input: RecipeAssemblyInput<'_>) -> Result<AssembledRecipe> {
    match input.recipe {
        VerificationRecipe::Inherit => assemble_inherit(input),
        VerificationRecipe::CleanRoom { .. } => assemble_clean_room(input).await,
    }
}

fn assemble_inherit(input: RecipeAssemblyInput<'_>) -> Result<AssembledRecipe> {
    let history = format_history_slice(input.history);
    let diff = proposed_diff(input.tool_name, input.original_args, input.cwd);
    let volatile_tail = format!("{}\n\n## Proposed change\n\n{diff}", input.inherit_framing);
    let prompt = format!("{history}\n\n{volatile_tail}");
    Ok(AssembledRecipe {
        prompt,
        stable_prefix: history,
        volatile_tail,
    })
}

async fn assemble_clean_room(input: RecipeAssemblyInput<'_>) -> Result<AssembledRecipe> {
    let (include_linked, last_n) = match input.recipe {
        VerificationRecipe::CleanRoom {
            include_linked_files,
            last_n_reads,
        } => (*include_linked_files, *last_n_reads),
        VerificationRecipe::Inherit => (input.include_linked_files, input.last_n_reads),
    };
    let last_n = if last_n == 0 {
        input.last_n_reads
    } else {
        last_n
    };
    let mut stable = String::new();
    if let Some((path, body)) = select_guidance_for_target(
        input.session,
        input.workspace_root,
        input.cwd,
        input.target_path,
        input.guidance_file_names,
    )
    .await
    {
        stable.push_str(&format!(
            "## Instructions ({})\n\n{body}\n",
            path.display()
        ));
        if include_linked {
            for (linked_path, linked_body) in resolve_linked_files(
                &path,
                &body,
                input.workspace_root,
            ) {
                stable.push_str(&format!(
                    "\n## Linked ({})\n\n{linked_body}\n",
                    linked_path.display()
                ));
            }
        }
    }
    let mut volatile = String::new();
    let reads = last_n_file_reads(input.session, last_n).await;
    if !reads.is_empty() {
        volatile.push_str("## Recent reads\n");
        for (path, excerpt) in reads {
            volatile.push_str(&format!("\n### {path}\n\n{excerpt}\n"));
        }
    }
    let diff = proposed_diff(input.tool_name, input.original_args, input.cwd);
    volatile.push_str(&format!("\n## Proposed change\n\n{diff}\n"));
    let prompt = format!("{stable}\n{volatile}");
    Ok(AssembledRecipe {
        prompt,
        stable_prefix: stable,
        volatile_tail: volatile,
    })
}

fn format_history_slice(history: &[Message]) -> String {
    serde_json::to_string(history).unwrap_or_else(|_| "[]".to_string())
}

pub fn proposed_diff(tool_name: &str, args: &Value, cwd: &Path) -> String {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .map(|p| if p.is_absolute() { p } else { cwd.join(p) });
    match tool_name {
        "write" | "plan_write" => {
            let new = args
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let old = path
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            unified_diff(&old, new)
        }
        "edit" | "plan_edit" => {
            let old = args
                .get("old_string")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let new = args
                .get("new_string")
                .and_then(Value::as_str)
                .unwrap_or_default();
            unified_diff(old, new)
        }
        _ => serde_json::to_string_pretty(args).unwrap_or_default(),
    }
}

/// Walk up from the target file's directory to its repo/worktree root,
/// matching `guidance_names`. Nested-repo files are used only when that
/// repo root's workspace_trust is `trust`. Fall back to session-cwd search.
pub async fn select_guidance_for_target(
    session: &Session,
    workspace_root: &Path,
    cwd: &Path,
    target_path: Option<&Path>,
    guidance_names: &[String],
) -> Option<(PathBuf, String)> {
    if let Some(target) = target_path {
        let start = if target.is_dir() {
            target.to_path_buf()
        } else {
            target.parent().unwrap_or(target).to_path_buf()
        };
        if let Some(found) = walk_guidance(&start, guidance_names)
            && guidance_is_trusted(session, workspace_root, &found.0).await
        {
            return Some(found);
        }
    }
    walk_guidance(cwd, guidance_names)
}

fn walk_guidance(start: &Path, names: &[String]) -> Option<(PathBuf, String)> {
    if names.is_empty() {
        return None;
    }
    let stop_at = crate::git::find_worktree_root(start);
    let mut dir: Option<&Path> = Some(start);
    while let Some(d) = dir {
        for name in names {
            let candidate = d.join(name);
            if candidate.is_file()
                && let Ok(body) = std::fs::read_to_string(&candidate)
            {
                return Some((candidate, body));
            }
        }
        if let Some(root) = &stop_at
            && d == root.as_path()
        {
            break;
        }
        dir = d.parent();
    }
    None
}

async fn guidance_is_trusted(session: &Session, workspace_root: &Path, guidance_path: &Path) -> bool {
    let Some(repo_root) = crate::git::find_worktree_root(guidance_path) else {
        return true;
    };
    let Ok(workspace) = workspace_root.canonicalize() else {
        return false;
    };
    let Ok(repo) = repo_root.canonicalize() else {
        return false;
    };
    if repo == workspace {
        return true;
    }
    match session.db.workspace_trust_by_root(&repo).await {
        Ok(Some(decision)) => decision.mode == WorkspaceTrustMode::Trust,
        _ => false,
    }
}

/// Extract markdown links and resolve each against (a) the instructions
/// file directory, (b) the instructions repo root (also serving
/// root-absolute `/docs/x.md` GitHub convention), (c) the workspace root.
/// Existence-validated, contained, deduped, capped. Fail-open to omission.
pub fn resolve_linked_files(
    instructions_path: &Path,
    instructions_body: &str,
    workspace_root: &Path,
) -> Vec<(PathBuf, String)> {
    let Ok(workspace) = workspace_root.canonicalize() else {
        return Vec::new();
    };
    let instructions_dir = instructions_path.parent().unwrap_or(instructions_path);
    let repo_root = crate::git::find_worktree_root(instructions_path)
        .unwrap_or_else(|| instructions_dir.to_path_buf());
    let links = extract_markdown_links(instructions_body);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut total_bytes = 0usize;
    for link in links {
        if out.len() >= MAX_LINKED_FILES {
            break;
        }
        let Some(resolved) = resolve_one_link(&link, instructions_dir, &repo_root, &workspace)
        else {
            continue;
        };
        if !seen.insert(resolved.clone()) {
            continue;
        }
        match std::fs::read_to_string(&resolved) {
            Ok(body) => {
                total_bytes = total_bytes.saturating_add(body.len());
                if total_bytes > MAX_LINKED_BYTES {
                    break;
                }
                out.push((resolved, body));
            }
            Err(_) => continue,
        }
    }
    out
}

fn extract_markdown_links(body: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(']') {
        let after = &rest[start + 1..];
        if let Some(stripped) = after.strip_prefix('(')
            && let Some(end) = stripped.find(')')
        {
            let raw = stripped[..end].trim();
            let href = raw.split_whitespace().next().unwrap_or(raw);
            let href = href.trim_matches('"').trim_matches('\'');
            if !href.is_empty()
                && !href.starts_with('#')
                && !href.contains("://")
                && !href.starts_with("mailto:")
            {
                links.push(href.to_string());
            }
            rest = &stripped[end + 1..];
            continue;
        }
        rest = after;
    }
    links
}

fn resolve_one_link(
    link: &str,
    instructions_dir: &Path,
    repo_root: &Path,
    workspace_root: &Path,
) -> Option<PathBuf> {
    let stripped = link.trim_start_matches('/');
    let bases = [
        instructions_dir.join(link),
        repo_root.join(stripped),
        workspace_root.join(stripped),
    ];
    for candidate in bases {
        if let Some(canonical) = contained_regular_file(&candidate, workspace_root) {
            return Some(canonical);
        }
    }
    None
}

fn contained_regular_file(path: &Path, workspace_root: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    let meta = std::fs::metadata(&canonical).ok()?;
    if !meta.is_file() {
        return None;
    }
    if canonical.starts_with(workspace_root) {
        Some(canonical)
    } else {
        None
    }
}

async fn last_n_file_reads(session: &Session, last_n: u8) -> Vec<(String, String)> {
    if last_n == 0 {
        return Vec::new();
    }
    let Ok(calls) = session.db.list_tool_calls_for_session(session.id).await else {
        return Vec::new();
    };
    calls
        .into_iter()
        .rev()
        .filter(|call| call.tool == "read")
        .take(last_n as usize)
        .filter_map(|call| {
            let path = call.path.clone().or_else(|| {
                call.wire_input_json
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })?;
            Some((path, call.output))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    fn session_at(root: &Path) -> Session {
        let db = crate::db::Db::open_in_memory().unwrap();
        Session::create_for_test(
            db,
            root.to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn clean_room_stable_prefix_precedes_volatile_tail_bytewise() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "# rules\nbe careful\n").unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn old() {}\n").unwrap();
        let session = session_at(tmp.path());
        let args = serde_json::json!({
            "path": "src.rs",
            "content": "fn new() {}\n"
        });
        let names = vec!["AGENTS.md".to_string()];
        let assembled = assemble_recipe(RecipeAssemblyInput {
            recipe: &VerificationRecipe::clean_room_default(),
            history: &[],
            session: &session,
            workspace_root: tmp.path(),
            cwd: tmp.path(),
            target_path: Some(&tmp.path().join("src.rs")),
            tool_name: "write",
            original_args: &args,
            guidance_file_names: &names,
            last_n_reads: 3,
            include_linked_files: false,
            inherit_framing: "",
        })
        .await
        .unwrap();
        assert!(
            assembled.prompt.starts_with(&assembled.stable_prefix),
            "stable prefix must lead the assembled prompt"
        );
        assert!(assembled.prompt.ends_with(&assembled.volatile_tail));
        assert!(assembled.stable_prefix.contains("be careful"));
        assert!(assembled.volatile_tail.contains("Proposed change"));
        let stable_end = assembled.stable_prefix.len();
        assert_eq!(
            &assembled.prompt[stable_end..].trim_start(),
            assembled.volatile_tail.trim_start()
        );
    }

    #[test]
    fn linked_files_resolve_across_three_bases_and_drop_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let github = tmp.path().join(".github");
        std::fs::create_dir_all(&github).unwrap();
        std::fs::write(tmp.path().join("docs-x.md"), "from repo root\n").unwrap();
        std::fs::write(
            github.join("copilot-instructions.md"),
            "See [root](/docs-x.md) and [missing](nope.md)\n",
        )
        .unwrap();
        let resolved = resolve_linked_files(
            &github.join("copilot-instructions.md"),
            "See [root](/docs-x.md) and [missing](nope.md)\n",
            tmp.path(),
        );
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].1.contains("from repo root"));
    }

    #[test]
    fn extract_markdown_links_ignores_urls_and_anchors() {
        let links = extract_markdown_links(
            "[a](../x.md) [b](https://ex) [c](#frag) [d](./y.md \"title\")",
        );
        assert_eq!(links, vec!["../x.md".to_string(), "./y.md".to_string()]);
    }
}
