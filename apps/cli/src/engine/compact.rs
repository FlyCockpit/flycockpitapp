//! `/compact` — fresh-thread handoff (`plan.md` T6.e, GOALS §10).
//!
//! `/compact` is **not** inline summarization. It assembles a handoff
//! prompt for a *brand-new* session and seeds it with the live working
//! set, then preserves the old session whole on disk. The pieces, in the
//! fixed engine ordering:
//!
//! 0. **Prune-first.** The driver runs `/prune` (lossless) before
//!    summarizing so the brief is drawn from a denser transcript. No
//!    `--no-prune` flag — ordering is fixed (handled in the driver).
//! 1. **Model brief.** The active model drafts a self-contained brief
//!    ([`brief_prompt`] builds the request).
//! 2. **Deterministic state appendix** ([`StateAppendix`]) — factual
//!    ledger from the runtime, not LLM-written: files read/edited with
//!    hashes, commands run with exit codes, git branch + dirty files,
//!    open todos, and pinned messages verbatim.
//! 3. **Seed-tools** ([`derive_seed_tools`]) — read-only, idempotent
//!    tool calls that reconstruct the working set. **Re-executed** in
//!    the new thread, never replayed from stale snapshots.
//! 4. **Pinned messages** — injected verbatim, never summarized.
//! 5. **Review then commit** — the assembled handoff goes into the
//!    composer; on confirm a new session is seeded with it.
//!
//! Everything in this module is deterministic and pure over its inputs
//! (the tool-call ledger + git state + pins), so it is unit-testable
//! without a live model or daemon.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::db::tool_calls::ToolCallEvent;

/// Read-only / idempotent tools eligible to be re-executed as seed-tools
/// in the new thread. Never `bash`, `write`, `edit` (GOALS §10). `read`
/// and the read-only intel tools reconstruct the working set; `ls` /
/// `git status` are surfaced through dedicated seed entries below.
const SEED_TOOLS: &[&str] = &[
    "read",
    "outline",
    "symbol_find",
    "word",
    "deps",
    "circular",
    "tree",
    "search",
    "impact",
];

fn is_seed_tool(name: &str) -> bool {
    SEED_TOOLS.contains(&name)
}

/// Whether `name` is a read-only / idempotent tool eligible to be emitted as
/// a seed and re-executed in another agent's context. Shared by the
/// `/compact` handoff and the re-queryable-subagent `seed` tool (GOALS §3c)
/// so both honor one allowlist. The sandboxed `grep`/`glob` (docs-answerer
/// only) are included as read-only for completeness; the driver re-exec is
/// the hard gate (it only dispatches a seed the *caller* actually holds).
pub fn is_read_only_seed_tool(name: &str) -> bool {
    is_seed_tool(name) || matches!(name, "grep" | "glob")
}

/// One seed-tool to re-execute at the start of the new thread. Carries
/// the tool name + the canonical args from the prior call; the new
/// session dispatches it fresh (never replays the old output).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeedTool {
    pub tool: String,
    pub args: Value,
}

/// The deterministic state appendix. Built from the runtime ledger, not
/// the model. Rendered to markdown and concatenated to the model brief.
#[derive(Debug, Clone, Default)]
pub struct StateAppendix {
    /// Files read this session (canonical paths), deduped + sorted.
    pub files_read: Vec<String>,
    /// Files written / edited this session, with the latest content
    /// hash when one is known.
    pub files_edited: Vec<FileEdit>,
    /// Commands run via `bash`, with exit status summary.
    pub commands: Vec<CommandRun>,
    /// Current git branch, if inside a repo.
    pub git_branch: Option<String>,
    /// Count of dirty files (staged + unstaged) at compaction time.
    pub dirty_files: Option<usize>,
    /// Open todos / unfinished items surfaced from the session, if any.
    pub open_todos: Vec<String>,
    /// Active persisted goal summary, if any.
    pub active_goal: Option<String>,
    /// Durable task-backed todo overview, rendered compactly by status.
    pub task_overview: Vec<String>,
    /// Pinned user messages, verbatim, in pin order.
    pub pinned_messages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    pub path: String,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRun {
    pub command: String,
    /// `true` when the call hard-failed (non-zero / tool error).
    pub failed: bool,
}

impl StateAppendix {
    /// Render to the markdown block that follows the model brief. Terse
    /// (token economy), factual, headed so a fresh agent can orient.
    pub fn render(&self) -> String {
        let mut out = String::from("\n\n---\n## State appendix (deterministic — runtime ledger)\n");

        if let Some(branch) = &self.git_branch {
            out.push_str(&format!("\n**Git branch:** `{branch}`"));
        }
        if let Some(dirty) = self.dirty_files {
            out.push_str(&format!("  ·  **Dirty files:** {dirty}"));
        }
        out.push('\n');

        if !self.files_edited.is_empty() {
            out.push_str("\n**Files written/edited:**\n");
            for f in &self.files_edited {
                match &f.hash {
                    Some(h) => out.push_str(&format!("- `{}` (hash {})\n", f.path, h)),
                    None => out.push_str(&format!("- `{}`\n", f.path)),
                }
            }
        }
        if !self.files_read.is_empty() {
            out.push_str("\n**Files read:**\n");
            for f in &self.files_read {
                out.push_str(&format!("- `{f}`\n"));
            }
        }
        if !self.commands.is_empty() {
            out.push_str("\n**Commands run:**\n");
            for c in &self.commands {
                let status = if c.failed { " — FAILED" } else { "" };
                out.push_str(&format!("- `{}`{status}\n", c.command));
            }
        }
        if !self.open_todos.is_empty() {
            out.push_str("\n**Open todos:**\n");
            for t in &self.open_todos {
                out.push_str(&format!("- {t}\n"));
            }
        }
        if let Some(goal) = &self.active_goal {
            out.push_str("\n**Active goal:**\n");
            out.push_str(goal);
            out.push('\n');
        }
        if !self.task_overview.is_empty() {
            out.push_str("\n**Task todo overview:**\n");
            for t in &self.task_overview {
                out.push_str(t);
                out.push('\n');
            }
            out.push_str("- Full details/notes: call `todo_read(id_or_name=...)`\n");
        }
        if !self.pinned_messages.is_empty() {
            out.push_str("\n**Pinned messages (verbatim — load-bearing):**\n");
            for m in &self.pinned_messages {
                out.push_str(&format!("> {}\n", m.replace('\n', "\n> ")));
            }
        }
        out
    }
}

/// Build the deterministic appendix from the session's tool-call ledger
/// plus the live git state and the pinned-message list.
///
/// `calls` is `Db::list_tool_calls_for_session` output. `cwd` is the
/// session's project root (for the git lookup). `pins` are verbatim
/// pinned user messages. `open_todos` come from any idle-continuation /
/// todo tracker the caller has (empty in v1).
pub fn build_appendix(
    calls: &[ToolCallEvent],
    cwd: &Path,
    pins: &[String],
    open_todos: &[String],
    active_goal: Option<String>,
) -> StateAppendix {
    let mut files_read: BTreeSet<String> = BTreeSet::new();
    let mut files_edited: Vec<FileEdit> = Vec::new();
    let mut commands: Vec<CommandRun> = Vec::new();

    for call in calls {
        match call.tool.as_str() {
            "read" | "readlock" => {
                if let Some(p) = call
                    .path
                    .clone()
                    .or_else(|| arg_path(&call.wire_input_json))
                {
                    files_read.insert(p);
                }
            }
            "write" | "writeunlock" | "edit" | "editunlock" => {
                if let Some(p) = call
                    .path
                    .clone()
                    .or_else(|| arg_path(&call.wire_input_json))
                {
                    let hash =
                        arg_hash(&call.wire_input_json).or_else(|| hash_from_output(&call.output));
                    record_edit(&mut files_edited, p, hash);
                }
            }
            "bash" => {
                if let Some(cmd) = call.wire_input_json.get("command").and_then(Value::as_str) {
                    commands.push(CommandRun {
                        command: crate::text::first_line_capped(cmd, 100),
                        failed: call.hard_fail,
                    });
                }
            }
            _ => {}
        }
    }

    let git_branch = crate::git::current_branch(cwd).ok().flatten();
    let dirty_files = crate::git::repo_status(cwd)
        .ok()
        .flatten()
        .map(|s| (s.staged + s.unstaged) as usize);

    StateAppendix {
        files_read: files_read.into_iter().collect(),
        files_edited,
        commands,
        git_branch,
        dirty_files,
        open_todos: open_todos.to_vec(),
        active_goal,
        task_overview: Vec::new(),
        pinned_messages: pins.to_vec(),
    }
}

pub fn render_task_todo_overview(
    overview: &crate::db::task_todos::TaskTodoOverview,
) -> Vec<String> {
    overview
        .items
        .iter()
        .map(|todo| {
            let name = todo.content.lines().next().unwrap_or("").trim();
            match todo.status {
                crate::db::task_todos::TodoStatus::Completed => format!(
                    "- Completed: {} - {} (`{}`)",
                    name,
                    todo.outcome_summary
                        .as_deref()
                        .unwrap_or("completed; details available"),
                    todo.id
                ),
                crate::db::task_todos::TodoStatus::InProgress => {
                    format!("- In progress: {} (`{}`)", name, todo.id)
                }
                crate::db::task_todos::TodoStatus::Pending => {
                    format!("- Pending: {} (`{}`)", name, todo.id)
                }
                crate::db::task_todos::TodoStatus::Cancelled => {
                    format!("- Cancelled: {} (`{}`)", name, todo.id)
                }
            }
        })
        .chain((overview.omitted > 0).then(|| {
            format!(
                "- Omitted lower-priority/completed todos: {}",
                overview.omitted
            )
        }))
        .collect()
}

/// Derive the seed-tool list: read-only / idempotent calls whose results
/// were the live working set just before compaction. We re-execute the
/// **most recent** identical (tool, args) call for every snapshot tool
/// the session used, so the new agent gets the current content without a
/// round-trip — but **never** replays the old output (the call is
/// re-dispatched in the new thread).
///
/// Restricted to [`SEED_TOOLS`]. Deduped by `(tool, canonical_args)` so
/// a file read five times yields one seed. Ordered by last use so the
/// most-relevant context lands first.
pub fn derive_seed_tools(calls: &[ToolCallEvent]) -> Vec<SeedTool> {
    // Last-occurrence index per identity, to dedup while keeping order.
    let mut last_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut order: Vec<(String, SeedTool)> = Vec::new();

    for call in calls {
        if !is_seed_tool(&call.tool) || call.hard_fail {
            continue;
        }
        let key = format!("{}\u{0}{}", call.tool, canonical(&call.wire_input_json));
        let seed = SeedTool {
            tool: call.tool.clone(),
            args: call.wire_input_json.clone(),
        };
        match last_index.get(&key).copied() {
            Some(i) => {
                order[i].1 = seed; // refresh to latest args (same identity)
            }
            None => {
                last_index.insert(key.clone(), order.len());
                order.push((key, seed));
            }
        }
    }
    order.into_iter().map(|(_, s)| s).collect()
}

/// Build the prompt sent to the model to draft the self-contained brief
/// (step 1). Terse instruction; the model's reply is the brief that gets
/// concatenated with the deterministic appendix.
///
/// `override_prompt` is the user's `extended.compact_prompt`: when it is
/// `Some` and non-empty (after trimming) it **fully replaces** the default
/// text; otherwise the hardcoded default is returned verbatim. The
/// deterministic appendix is assembled separately and is unaffected
/// (implementation note).
pub fn brief_prompt(override_prompt: Option<&str>) -> String {
    if let Some(custom) = override_prompt
        && !custom.trim().is_empty()
    {
        return custom.to_string();
    }
    "Write a self-contained handoff brief for a fresh agent with no memory of \
     this conversation, so it can continue the work from where we left off. \
     Cover: the goal, what's been done, what's left, and any decisions or \
     constraints that matter. Be concise and concrete. Do not list files or \
     commands — a deterministic appendix covers those."
        .to_string()
}

/// Assemble the full review-ready handoff: model brief + deterministic
/// appendix. (Seed-tools are surfaced separately; they re-execute, they
/// aren't part of the prose.)
pub fn assemble_handoff(brief: &str, appendix: &StateAppendix) -> String {
    format!("{}{}", brief.trim(), appendix.render())
}

// ---- helpers ---------------------------------------------------------------

/// Append (or refresh) one file-edit record into `edited`, keyed by path:
/// a path seen for the first time is pushed; a repeat updates the stored
/// hash when the later call carries one (later call wins). Shared by the
/// `/compact` appendix and the structured-return `files_changed` ledger
/// ([`crate::engine::envelope`]) so both derive the edited set the same way.
pub(crate) fn record_edit(edited: &mut Vec<FileEdit>, path: String, hash: Option<String>) {
    if let Some(existing) = edited.iter_mut().find(|f| f.path == path) {
        if hash.is_some() {
            existing.hash = hash;
        }
    } else {
        edited.push(FileEdit { path, hash });
    }
}

pub(crate) fn arg_path(args: &Value) -> Option<String> {
    args.get("path").and_then(Value::as_str).map(str::to_string)
}

pub(crate) fn arg_hash(args: &Value) -> Option<String> {
    args.get("hash").and_then(Value::as_str).map(str::to_string)
}

/// Pull a `[hash=<hex> ...]` token out of a tool output header (range
/// reads / writes emit one). Best-effort.
pub(crate) fn hash_from_output(output: &str) -> Option<String> {
    let start = output.find("hash=")? + "hash=".len();
    let rest = &output[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(rest[..end].to_string())
    }
}

fn canonical(args: &Value) -> String {
    fn sort_value(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    sorted.insert(k.clone(), sort_value(&map[k]));
                }
                Value::Object(sorted)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort_value).collect()),
            other => other.clone(),
        }
    }
    sort_value(args).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn call(
        tool: &str,
        args: Value,
        path: Option<&str>,
        output: &str,
        failed: bool,
    ) -> ToolCallEvent {
        ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            call_id: Uuid::new_v4().to_string(),
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: 0,
            model: String::new(),
            provider: String::new(),
            project_id: String::new(),
            project_root: String::new(),
            agent: "builder".into(),
            tool: tool.into(),
            path: path.map(str::to_string),
            recovery: crate::engine::repair::Recovery::Clean,
            hard_fail: failed,
            original_input_json: args.clone(),
            wire_input_json: args,
            output: output.into(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        }
    }

    #[test]
    fn appendix_collects_reads_edits_commands() {
        let calls = vec![
            call(
                "read",
                json!({"path": "/a.rs"}),
                Some("/a.rs"),
                "body",
                false,
            ),
            call(
                "read",
                json!({"path": "/a.rs"}),
                Some("/a.rs"),
                "body",
                false,
            ),
            call(
                "write",
                json!({"path": "/b.rs"}),
                Some("/b.rs"),
                "[hash=abc123 ok]",
                false,
            ),
            call("bash", json!({"command": "cargo test"}), None, "ok", false),
            call("bash", json!({"command": "cargo build"}), None, "err", true),
        ];
        let appendix = build_appendix(&calls, Path::new("/nonexistent-xyz"), &[], &[], None);
        // Reads deduped.
        assert_eq!(appendix.files_read, vec!["/a.rs".to_string()]);
        // Edit captured with hash from output header.
        assert_eq!(appendix.files_edited.len(), 1);
        assert_eq!(appendix.files_edited[0].path, "/b.rs");
        assert_eq!(appendix.files_edited[0].hash.as_deref(), Some("abc123"));
        // Both commands, failure flagged.
        assert_eq!(appendix.commands.len(), 2);
        assert!(!appendix.commands[0].failed);
        assert!(appendix.commands[1].failed);
    }

    #[test]
    fn appendix_renders_pins_verbatim() {
        let appendix = StateAppendix {
            pinned_messages: vec!["use the v2 API only".into()],
            ..Default::default()
        };
        let rendered = appendix.render();
        assert!(rendered.contains("Pinned messages"));
        assert!(rendered.contains("use the v2 API only"));
    }

    #[test]
    fn seed_tools_only_read_only_and_deduped() {
        let calls = vec![
            call("read", json!({"path": "/a.rs"}), Some("/a.rs"), "x", false),
            call("read", json!({"path": "/a.rs"}), Some("/a.rs"), "x", false),
            call("bash", json!({"command": "ls"}), None, "x", false),
            call("write", json!({"path": "/b.rs"}), Some("/b.rs"), "x", false),
            call("outline", json!({"path": "/a.rs"}), None, "x", false),
            // A failed read is not a trustworthy seed.
            call("read", json!({"path": "/c.rs"}), Some("/c.rs"), "err", true),
        ];
        let seeds = derive_seed_tools(&calls);
        // read /a.rs (deduped) + outline /a.rs — bash, write, failed read excluded.
        assert_eq!(seeds.len(), 2);
        assert!(seeds.iter().any(|s| s.tool == "read"));
        assert!(seeds.iter().any(|s| s.tool == "outline"));
        assert!(!seeds.iter().any(|s| s.tool == "bash" || s.tool == "write"));
    }

    #[test]
    fn assemble_handoff_concats_brief_and_appendix() {
        let appendix = StateAppendix {
            files_read: vec!["/a.rs".into()],
            ..Default::default()
        };
        let h = assemble_handoff("Continue the refactor.", &appendix);
        assert!(h.starts_with("Continue the refactor."));
        assert!(h.contains("State appendix"));
        assert!(h.contains("/a.rs"));
    }

    #[test]
    fn task_todo_overview_renders_completed_active_and_retrieval_tool() {
        let completed = crate::db::task_todos::TaskTodo {
            id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            content: "wire todo deltas".into(),
            status: crate::db::task_todos::TodoStatus::Completed,
            priority: 1,
            position: 0,
            outcome_summary: Some("delta applied".into()),
            version: 1,
        };
        let pending = crate::db::task_todos::TaskTodo {
            id: uuid::Uuid::new_v4(),
            session_id: completed.session_id,
            content: "finish retrieval".into(),
            status: crate::db::task_todos::TodoStatus::Pending,
            priority: 2,
            position: 1,
            outcome_summary: None,
            version: 0,
        };
        let overview = crate::db::task_todos::TaskTodoOverview {
            total: 3,
            omitted: 1,
            items: vec![completed, pending],
        };
        let mut appendix = StateAppendix::default();
        appendix.task_overview = render_task_todo_overview(&overview);
        let rendered = appendix.render();
        assert!(rendered.contains("Completed: wire todo deltas - delta applied"));
        assert!(rendered.contains("Pending: finish retrieval"));
        assert!(rendered.contains("todo_read(id_or_name=...)"));
        assert!(rendered.contains("Omitted lower-priority/completed todos: 1"));
    }

    /// The default brief prompt (no override) is the verbatim hardcoded text.
    /// Regression guard: a refactor that loses the default must trip this.
    #[test]
    fn brief_prompt_default_when_no_override() {
        let expected = "Write a self-contained handoff brief for a fresh agent with no memory of \
             this conversation, so it can continue the work from where we left off. \
             Cover: the goal, what's been done, what's left, and any decisions or \
             constraints that matter. Be concise and concrete. Do not list files or \
             commands — a deterministic appendix covers those.";
        assert_eq!(brief_prompt(None), expected);
        // An empty / whitespace-only override is treated as unset (the
        // "empty string == unset" edge case): the default is returned.
        assert_eq!(brief_prompt(Some("")), expected);
        assert_eq!(brief_prompt(Some("   \n  ")), expected);
    }

    /// A non-empty override fully replaces the default brief prompt.
    #[test]
    fn brief_prompt_override_replaces_default() {
        let custom = "Summarize what we did in two sentences.";
        assert_eq!(brief_prompt(Some(custom)), custom);
        // Verbatim — not appended to the default.
        assert!(!brief_prompt(Some(custom)).contains("deterministic appendix"));
    }
}
