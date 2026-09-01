//! Inherit and clean-room recipe assembly for ArtifactWrite verification.
//!
//! Clean-room guidance selection is target-anchored and trust-gated
//! (decision 11). Linked files are resolved against three bases, existence-
//! validated, contained under the workspace root, and capped.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;

use crate::agents::{VerificationRecipe, VerificationToolCategory};
use crate::db::tool_calls::ToolCallEvent;
use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::engine::guidance_diff::unified_diff;
use crate::session::Session;

const MAX_LINKED_FILES: usize = 8;
const MAX_LINKED_BYTES: usize = 256 * 1024;

/// A clean-room projection cannot safely proceed without its durable goal.
///
/// Keep the failure typed so all callers retain the durable-goal context when
/// propagating recipe-assembly errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CleanRoomSessionGoalError {
    #[error("loading persisted session goal for clean-room verification: {0}")]
    Load(anyhow::Error),
    #[error("clean-room verification requires a persisted session goal")]
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRecipe {
    /// Stable-parts-first body (session goal + instructions + linked files)
    /// then volatile tail (curated results + proposed diff). The stable prefix
    /// is intended to cache across verifications.
    pub prompt: String,
    pub stable_prefix: String,
    pub volatile_tail: String,
}

#[derive(Clone)]
pub struct RecipeAssemblyInput<'a> {
    pub recipe: &'a VerificationRecipe,
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

/// A full transcript is meaningful only when the generator shares the
/// author's slot (and therefore its cache/prompt identity). Foreign slots
/// always receive the default curated clean-room projection, even when the
/// configured recipe says `Inherit`.
pub(crate) fn generator_recipe_for_slot<'a>(
    recipe: &'a VerificationRecipe,
    same_as_author: bool,
) -> Cow<'a, VerificationRecipe> {
    if same_as_author || !matches!(recipe, VerificationRecipe::Inherit) {
        Cow::Borrowed(recipe)
    } else {
        Cow::Owned(VerificationRecipe::clean_room_default())
    }
}

fn assemble_inherit(input: RecipeAssemblyInput<'_>) -> Result<AssembledRecipe> {
    let diff = proposed_diff(input.tool_name, input.original_args, input.cwd);
    let volatile_tail = format!("{}\n\n## Proposed change\n\n{diff}", input.inherit_framing);
    Ok(AssembledRecipe {
        prompt: volatile_tail.clone(),
        stable_prefix: String::new(),
        volatile_tail,
    })
}

async fn assemble_clean_room(input: RecipeAssemblyInput<'_>) -> Result<AssembledRecipe> {
    let (include_linked, last_n, tool_categories, tool_allowlist) = match input.recipe {
        VerificationRecipe::CleanRoom {
            include_linked_files,
            last_n_reads,
            tool_categories,
            tool_allowlist,
        } => (
            *include_linked_files,
            *last_n_reads,
            tool_categories.as_slice(),
            tool_allowlist.as_slice(),
        ),
        VerificationRecipe::Inherit => (input.include_linked_files, input.last_n_reads, &[], &[]),
    };
    let last_n = if last_n == 0 {
        input.last_n_reads
    } else {
        last_n
    };
    let mut stable = String::new();
    let goal = stored_session_goal(input.session).await?;
    stable.push_str(&format!("## Session goal\n\n{goal}\n"));
    if let Some((path, body)) = select_guidance_for_target(
        input.session,
        input.workspace_root,
        input.cwd,
        input.target_path,
        input.guidance_file_names,
    )
    .await
    {
        stable.push_str(&format!("## Instructions ({})\n\n{body}\n", path.display()));
        if include_linked {
            for (linked_path, linked_body) in
                resolve_linked_files(&path, &body, input.workspace_root)
            {
                stable.push_str(&format!(
                    "\n## Linked ({})\n\n{linked_body}\n",
                    linked_path.display()
                ));
            }
        }
    }
    let mut volatile = String::new();
    let results = curated_tool_results(
        input.session,
        last_n,
        tool_categories,
        tool_allowlist,
        input.target_path,
    )
    .await?;
    if !results.is_empty() {
        volatile.push_str("## Curated investigation results\n");
        for result in results {
            volatile.push_str(&format!(
                "\n### {}\n\n{}\n",
                result.provenance, result.output
            ));
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

pub fn proposed_diff(tool_name: &str, args: &Value, cwd: &Path) -> String {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .map(|p| if p.is_absolute() { p } else { cwd.join(p) });
    match tool_name {
        "write" => {
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
        "edit" => {
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
        let requested_start = if target.is_dir() {
            target.to_path_buf()
        } else {
            target.parent().unwrap_or(target).to_path_buf()
        };
        let mut start = requested_start.as_path();
        while !start.exists() {
            let Some(parent) = start.parent() else {
                break;
            };
            start = parent;
        }
        if let Some(found) = walk_guidance(start, guidance_names, workspace_root)
            && guidance_is_trusted(session, workspace_root, &found.0).await
        {
            return Some(found);
        }
    }
    let fallback = walk_guidance(cwd, guidance_names, workspace_root)?;
    guidance_is_trusted(session, workspace_root, &fallback.0)
        .await
        .then_some(fallback)
}

fn walk_guidance(
    start: &Path,
    names: &[String],
    workspace_root: &Path,
) -> Option<(PathBuf, String)> {
    if names.is_empty() {
        return None;
    }
    let Ok(workspace) = workspace_root.canonicalize() else {
        return None;
    };
    let stop_at = crate::git::find_worktree_root(start)
        .and_then(|root| root.canonicalize().ok())
        .unwrap_or_else(|| workspace.clone());
    let mut dir: Option<&Path> = Some(start);
    while let Some(d) = dir {
        for name in names {
            let candidate = d.join(name);
            if candidate.is_file()
                && let Ok(body) = std::fs::read_to_string(&candidate)
                && let Some(canonical) = contained_regular_file(&candidate, &workspace)
            {
                return Some((canonical, body));
            }
        }
        let reached_stop = d
            .canonicalize()
            .ok()
            .is_some_and(|canonical| canonical == stop_at);
        if reached_stop {
            break;
        }
        let Some(parent) = d.parent() else {
            break;
        };
        if parent
            .canonicalize()
            .ok()
            .is_some_and(|canonical| !canonical.starts_with(&workspace))
            || !path_is_under(parent, &workspace)
        {
            break;
        }
        dir = Some(parent);
    }
    None
}

fn path_is_under(path: &Path, workspace: &Path) -> bool {
    path.starts_with(workspace)
        || path
            .canonicalize()
            .ok()
            .is_some_and(|canonical| canonical.starts_with(workspace))
}

async fn guidance_is_trusted(
    session: &Session,
    workspace_root: &Path,
    guidance_path: &Path,
) -> bool {
    let Ok(workspace) = workspace_root.canonicalize() else {
        return false;
    };
    if contained_regular_file(guidance_path, &workspace).is_none() {
        return false;
    }
    let Some(repo_root) = crate::git::find_worktree_root(guidance_path) else {
        // Contained in the session workspace and not a nested git repo:
        // the workspace itself is the trust root.
        return true;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CuratedToolResult {
    provenance: String,
    output: String,
}

async fn stored_session_goal(session: &Session) -> Result<String> {
    let goal = session
        .db
        .current_session_goal(session.id, false)
        .await
        .map_err(CleanRoomSessionGoalError::Load)?
        .ok_or(CleanRoomSessionGoalError::Missing)?;
    let mut task = goal.objective;
    if let Some(context) = goal.context.filter(|context| !context.trim().is_empty()) {
        task.push_str("\n\nContext:\n");
        task.push_str(&context);
    }
    Ok(task)
}

async fn curated_tool_results(
    session: &Session,
    last_n: u8,
    tool_categories: &[VerificationToolCategory],
    tool_allowlist: &[String],
    target_path: Option<&Path>,
) -> Result<Vec<CuratedToolResult>> {
    if last_n == 0 {
        return Ok(Vec::new());
    }
    let calls = session.db.list_tool_calls_for_session(session.id).await?;
    Ok(curate_tool_calls(
        calls,
        last_n,
        tool_categories,
        tool_allowlist,
        target_path,
    ))
}

fn curate_tool_calls(
    calls: Vec<ToolCallEvent>,
    last_n: u8,
    tool_categories: &[VerificationToolCategory],
    tool_allowlist: &[String],
    target_path: Option<&Path>,
) -> Vec<CuratedToolResult> {
    let mut selected = calls
        .into_iter()
        .enumerate()
        .filter(|(_, call)| tool_is_selected(call, tool_categories, tool_allowlist))
        .map(|(index, call)| {
            let relevant = tool_result_is_relevant(&call, target_path);
            (index, relevant, call)
        })
        .collect::<Vec<_>>();
    // Relevance wins over recency; within either group, newest results win.
    selected.sort_by_key(|(index, relevant, _)| {
        (std::cmp::Reverse(*relevant), std::cmp::Reverse(*index))
    });
    selected.truncate(last_n as usize);
    selected.sort_by_key(|(index, _, _)| *index);
    selected
        .into_iter()
        .map(|(_, _, call)| CuratedToolResult {
            provenance: tool_result_provenance(&call),
            output: call.output,
        })
        .collect()
}

fn tool_is_selected(
    call: &ToolCallEvent,
    tool_categories: &[VerificationToolCategory],
    tool_allowlist: &[String],
) -> bool {
    tool_allowlist.iter().any(|tool| tool == &call.tool)
        || tool_categories.iter().any(|category| match category {
            VerificationToolCategory::Reads => call.tool == "read",
            VerificationToolCategory::Exploration => {
                matches!(
                    call.tool.as_str(),
                    "code" | "graph" | "search" | "grep" | "glob"
                )
            }
        })
}

fn tool_result_is_relevant(call: &ToolCallEvent, target_path: Option<&Path>) -> bool {
    let Some(target_path) = target_path else {
        return false;
    };
    let target = target_path.to_string_lossy();
    let file_name = target_path.file_name().and_then(|name| name.to_str());
    let matches_subject = |value: &str| {
        value == target.as_ref()
            || value.ends_with(target.as_ref())
            || file_name.is_some_and(|name| value.contains(name))
    };
    call.path.as_deref().is_some_and(matches_subject)
        || ["path", "pattern", "query", "name", "token"]
            .into_iter()
            .filter_map(|field| call.wire_input_json.get(field).and_then(Value::as_str))
            .any(matches_subject)
        || matches_subject(&call.output)
}

fn tool_result_provenance(call: &ToolCallEvent) -> String {
    let args = &call.wire_input_json;
    let path = call
        .path
        .as_deref()
        .or_else(|| args.get("path").and_then(Value::as_str));
    let query = ["pattern", "query", "name", "token"]
        .into_iter()
        .find_map(|field| args.get(field).and_then(Value::as_str));
    let mut fields = Vec::new();
    if let Some(path) = path {
        fields.push(format!("path: {path}"));
    }
    if let Some(query) = query {
        fields.push(format!("query: {query}"));
    }
    if let (Some(start), Some(end)) = (
        args.get("start_line").and_then(Value::as_u64),
        args.get("end_line").and_then(Value::as_u64),
    ) {
        fields.push(format!("range: lines {start}-{end}"));
    } else if let Some(offset) = args.get("offset").and_then(Value::as_u64) {
        let limit = args.get("limit").and_then(Value::as_u64);
        fields.push(match limit {
            Some(limit) => format!("range: offset {offset}, limit {limit}"),
            None => format!("range: offset {offset}"),
        });
    }
    if let Some(kind) = args.get("kind").and_then(Value::as_str) {
        fields.push(format!("kind: {kind}"));
    }
    if fields.is_empty() {
        format!("{} result", call.tool)
    } else {
        format!("{} result — {}", call.tool, fields.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tool_calls::Recovery;
    use crate::session::Session;
    use uuid::Uuid;

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

    #[test]
    fn foreign_inherit_uses_the_default_clean_room_recipe() {
        let inherit = VerificationRecipe::Inherit;
        assert_eq!(
            generator_recipe_for_slot(&inherit, false).as_ref(),
            &VerificationRecipe::clean_room_default()
        );
        assert_eq!(
            generator_recipe_for_slot(&inherit, true).as_ref(),
            &VerificationRecipe::Inherit
        );
    }

    fn tool_call(
        session: &Session,
        tool: &str,
        timestamp: i64,
        path: Option<&str>,
        args: Value,
        output: &str,
    ) -> ToolCallEvent {
        ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: session.id,
            call_id: format!("{tool}-{timestamp}"),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp,
            model: "test-model".into(),
            provider: "test-provider".into(),
            project_id: session.project_id.clone(),
            project_root: session.project_root.display().to_string(),
            agent: "Build".into(),
            tool: tool.into(),
            mcp_server: None,
            path: path.map(str::to_string),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: args.clone(),
            wire_input_json: args,
            output: output.into(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            shape_fingerprint: None,
            hint: None,
        }
    }

    #[tokio::test]
    async fn clean_room_carries_the_persisted_session_goal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn old() {}\n").unwrap();
        let session = session_at(tmp.path());
        session
            .db
            .create_session_goal(
                session.id,
                &session.project_id,
                "Preserve the atomic write contract.",
                Some("Do not change the public API."),
                None,
            )
            .await
            .unwrap();
        let args = serde_json::json!({ "path": "src.rs", "content": "fn new() {}\n" });
        let assembled = assemble_recipe(RecipeAssemblyInput {
            recipe: &VerificationRecipe::clean_room_default(),
            session: &session,
            workspace_root: tmp.path(),
            cwd: tmp.path(),
            target_path: Some(&tmp.path().join("src.rs")),
            tool_name: "write",
            original_args: &args,
            guidance_file_names: &[],
            last_n_reads: 5,
            include_linked_files: false,
            inherit_framing: "",
        })
        .await
        .unwrap();

        assert!(assembled.prompt.contains("## Session goal"));
        assert!(
            assembled
                .prompt
                .contains("Preserve the atomic write contract.")
        );
        assert!(assembled.prompt.contains("Do not change the public API."));
    }

    #[tokio::test]
    async fn clean_room_fails_closed_without_a_persisted_session_goal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn old() {}\n").unwrap();
        let session = session_at(tmp.path());
        let args = serde_json::json!({ "path": "src.rs", "content": "fn new() {}\n" });

        let error = assemble_recipe(RecipeAssemblyInput {
            recipe: &VerificationRecipe::clean_room_default(),
            session: &session,
            workspace_root: tmp.path(),
            cwd: tmp.path(),
            target_path: Some(&tmp.path().join("src.rs")),
            tool_name: "write",
            original_args: &args,
            guidance_file_names: &[],
            last_n_reads: 5,
            include_linked_files: false,
            inherit_framing: "",
        })
        .await
        .expect_err("clean-room verification must require a stored goal");

        assert!(
            error
                .to_string()
                .contains("requires a persisted session goal"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn inherit_recipe_remains_a_full_history_generator_path() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn old() {}\n").unwrap();
        let session = session_at(tmp.path());
        let args = serde_json::json!({ "path": "src.rs", "content": "fn new() {}\n" });
        let assembled = assemble_recipe(RecipeAssemblyInput {
            recipe: &VerificationRecipe::Inherit,
            session: &session,
            workspace_root: tmp.path(),
            cwd: tmp.path(),
            target_path: Some(&tmp.path().join("src.rs")),
            tool_name: "write",
            original_args: &args,
            guidance_file_names: &[],
            last_n_reads: 5,
            include_linked_files: false,
            inherit_framing: "Produce an alternative implementation.",
        })
        .await
        .unwrap();

        assert!(
            assembled
                .prompt
                .contains("Produce an alternative implementation.")
        );
        assert!(assembled.prompt.contains("## Proposed change"));
        assert!(!assembled.prompt.contains("## Session goal"));
    }

    #[test]
    fn curated_results_prefer_subject_relevance_and_keep_only_output_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session_at(tmp.path());
        let target = tmp.path().join("src/target.rs");
        let calls = vec![
            tool_call(
                &session,
                "search",
                1,
                Some("src"),
                serde_json::json!({
                    "path": "src",
                    "pattern": "target.rs",
                    "internal_invocation_marker": "must-not-project"
                }),
                "src/target.rs:12: target evidence",
            ),
            tool_call(
                &session,
                "read",
                2,
                Some("src/unrelated.rs"),
                serde_json::json!({ "path": "src/unrelated.rs" }),
                "unrelated evidence",
            ),
        ];

        let results = curate_tool_calls(
            calls,
            1,
            &[
                VerificationToolCategory::Reads,
                VerificationToolCategory::Exploration,
            ],
            &[],
            Some(&target),
        );

        assert_eq!(results.len(), 1);
        assert!(results[0].provenance.contains("search result"));
        assert!(results[0].provenance.contains("path: src"));
        assert!(results[0].provenance.contains("query: target.rs"));
        assert_eq!(results[0].output, "src/target.rs:12: target evidence");
        assert!(!results[0].provenance.contains("internal_invocation_marker"));
    }

    #[test]
    fn curated_result_categories_and_custom_allowlist_are_honored() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session_at(tmp.path());
        let calls = vec![
            tool_call(
                &session,
                "read",
                1,
                Some("src/lib.rs"),
                serde_json::json!({ "path": "src/lib.rs" }),
                "read result",
            ),
            tool_call(
                &session,
                "context_pack",
                2,
                None,
                serde_json::json!({ "topic": "verification" }),
                "custom result",
            ),
        ];

        let custom = curate_tool_calls(calls.clone(), 5, &[], &["context_pack".to_string()], None);
        assert_eq!(custom.len(), 1);
        assert_eq!(custom[0].output, "custom result");

        let reads = curate_tool_calls(calls, 5, &[VerificationToolCategory::Reads], &[], None);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].output, "read result");
    }

    #[tokio::test]
    async fn clean_room_stable_prefix_precedes_volatile_tail_bytewise() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "# rules\nbe careful\n").unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn old() {}\n").unwrap();
        let session = session_at(tmp.path());
        session
            .db
            .create_session_goal(
                session.id,
                &session.project_id,
                "Keep the change safe.",
                None,
                None,
            )
            .await
            .unwrap();
        let args = serde_json::json!({
            "path": "src.rs",
            "content": "fn new() {}\n"
        });
        let names = vec!["AGENTS.md".to_string()];
        let assembled = assemble_recipe(RecipeAssemblyInput {
            recipe: &VerificationRecipe::clean_room_default(),
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
            assembled.prompt[stable_end..].trim_start(),
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
        let links =
            extract_markdown_links("[a](../x.md) [b](https://ex) [c](#frag) [d](./y.md \"title\")");
        assert_eq!(links, vec!["../x.md".to_string(), "./y.md".to_string()]);
    }

    #[tokio::test]
    async fn guidance_walk_stops_at_workspace_when_the_target_has_no_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "OUTSIDE WORKSPACE\n").unwrap();
        let workspace = tmp.path().join("proj");
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/x.rs"), "fn x() {}\n").unwrap();
        let session = session_at(&workspace);
        let names = vec!["AGENTS.md".to_string()];
        let selected = select_guidance_for_target(
            &session,
            &workspace,
            &workspace,
            Some(&workspace.join("src/x.rs")),
            &names,
        )
        .await;
        assert!(
            selected.is_none(),
            "without a worktree the walk must not load guidance outside project_root, got {selected:?}"
        );
    }

    #[tokio::test]
    async fn guidance_walk_uses_workspace_contained_file_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "OUTSIDE\n").unwrap();
        let workspace = tmp.path().join("proj");
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("AGENTS.md"), "INSIDE\n").unwrap();
        std::fs::write(workspace.join("src/x.rs"), "fn x() {}\n").unwrap();
        let session = session_at(&workspace);
        let names = vec!["AGENTS.md".to_string()];
        let selected = select_guidance_for_target(
            &session,
            &workspace,
            &workspace,
            Some(&workspace.join("src/x.rs")),
            &names,
        )
        .await
        .expect("workspace-contained guidance is selectable");
        assert!(
            selected.1.contains("INSIDE"),
            "must prefer the contained file, got {}",
            selected.1
        );
        assert!(
            !selected.1.contains("OUTSIDE"),
            "must not load the parent of project_root"
        );
    }

    #[tokio::test]
    async fn curated_tool_results_propagates_projection_storage_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session_at(tmp.path());
        session
            .db
            .write(|conn| {
                conn.execute_batch(
                    "ALTER TABLE tool_call_events
                     RENAME TO tool_call_events_unavailable;",
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let error =
            curated_tool_results(&session, 1, &[VerificationToolCategory::Reads], &[], None)
                .await
                .expect_err("projection storage read failures must not turn into empty evidence");
        assert!(
            error
                .to_string()
                .contains("no such table: tool_call_events"),
            "{error:#}"
        );
    }
}
