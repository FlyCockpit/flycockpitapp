use super::*;

/// Gate a `spawn` request (GOALS §24): enforce the required `write_scope`
/// and the hard depth ceiling (clamp, don't crash). Returns
/// `Ok(child_depth)` (= `parent_depth + 1`) when the spawn is admissible, or
/// `Err(refusal_text)` — the tool result telling the model to do the slice's
/// work itself as a leaf — when `write_scope` is missing or the child would
/// exceed the ceiling. Pure so the gate is unit-testable without a driver.
///
/// This is only the syntactic gate. Durable authority containment (strict
/// sub-scope of the parent's *effective* authority, backend capability,
/// execution-wide permit, containment) is decided by
/// [`crate::write_scope`]'s coordinator before any child record, token, or
/// event exists.
pub(super) fn spawn_gate(
    parent_depth: u32,
    max_depth: u32,
    write_scope: &str,
) -> std::result::Result<u32, String> {
    if write_scope.trim().is_empty() {
        return Err(
            "refused: `write_scope` is required — delegating transfers a strict subtree of your \
             own write authority to the child. Give this child a dedicated workspace-relative \
             directory subtree and retry."
                .to_string(),
        );
    }
    let child_depth = parent_depth + 1;
    if child_depth > max_depth {
        return Err(format!(
            "refused: depth ceiling {max_depth} reached (you are at depth {parent_depth}). Do \
             this slice's work yourself as a leaf instead of delegating."
        ));
    }
    Ok(child_depth)
}

/// Fail closed on strict *writable* delegation.
///
/// Handing a child its own write scope is an authority transfer: the parent is
/// excluded from that subtree while the child runs. That exclusivity can only
/// be honored by a filesystem backend able to isolate arbitrary child syscalls,
/// and the direct workspace cannot — a child can hard-link its way to another
/// owner's inode without passing through any Cockpit check
/// (see [`crate::write_scope::backend`]).
///
/// So a write-capable worker is refused here, before any child record, token,
/// or event exists. Workers holding no Cockpit write tools
/// ([`crate::engine::schedule::authority::SpawnWorkerKind::Scout`]) are
/// unaffected: they receive no transferred authority. That is not the same as
/// being unable to write — see
/// [`crate::engine::schedule::authority::SpawnWorkerKind::is_write_capable`].
///
/// Returns `Some(refusal_text)` when the spawn must be refused.
pub(crate) fn scoped_write_refusal(
    worker: crate::engine::schedule::authority::SpawnWorkerKind,
    workspace_root: &std::path::Path,
    write_scope: &str,
    backend: &dyn crate::write_scope::backend::ScopedWriteBackend,
) -> Option<String> {
    use crate::write_scope::backend::ExecutionMode;
    use crate::write_scope::scope::CanonicalScope;

    // Scope containment is validated for EVERY worker, including those with no
    // Cockpit write tools. Such a child receives no transferred authority, but
    // `write_scope` still names a real subtree of this workspace, and a
    // `../outside` or symlink escape must never reach scheduling unvalidated.
    let scope = match CanonicalScope::resolve_under(workspace_root, write_scope) {
        Ok(scope) => scope,
        Err(err) => {
            return Some(format!(
                "refused: `write_scope` is not a usable subtree of this workspace — {err}. Give \
                 the child a workspace-relative directory inside your own write authority."
            ));
        }
    };

    // Only a write-capable child needs the isolation capability: it is the one
    // receiving exclusive authority.
    if !worker.is_write_capable() {
        return None;
    }

    // Probe the caller's backend rather than hard-coding the answer. The driver
    // passes the coordinator's own backend, so this fast gate and the durable
    // transfer in `run_swarm` always agree; a future Proven backend lights both
    // up together.
    let capability = backend.capability_for(&scope, ExecutionMode::Native);
    if capability.is_proven() {
        return None;
    }

    Some(
        "refused: scoped writes are unsupported on this workspace, so a write-capable child \
         cannot be given exclusive authority over a subtree. Cockpit cannot prove that another \
         process will not reach inside the delegated scope through a hard link or an ancestor \
         rename, so it fails closed rather than pretending the scope is exclusive. Do this \
         slice's work yourself, or delegate a reviewer that needs no write tools (note that \
         such a child can still write via `bash` within the session cwd)."
            .to_string(),
    )
}

/// True when `msg` is one half of a tracked skill pair — an assistant
/// message whose sole content is a `skill` ToolCall in `ids`, or its matching
/// user tool_result. Used by [`Driver::strip_abandoned_skill_pairs`] to drop
/// both halves of an abandoned skill pair together (the seam pushes each pair
/// as a standalone assistant turn + its result, so this never strips an
/// unrelated message). Assistant turns carrying anything beyond the tracked
/// skill call are left intact — the call/result wouldn't be cleanly removable
/// without breaking pairing.
pub(super) fn message_references_call_id(
    msg: &Message,
    ids: &std::collections::HashSet<String>,
) -> bool {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;
    match msg {
        Message::Assistant { content, .. } => {
            let calls: Vec<&str> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.id.as_str()),
                    _ => None,
                })
                .collect();
            // Strip only when the turn is exactly the tracked skill call and
            // nothing else (the seam pushes it as a standalone assistant turn).
            content.len() == 1 && calls.iter().all(|id| ids.contains(*id)) && !calls.is_empty()
        }
        Message::User { content } => content.iter().any(|c| match c {
            UserContent::ToolResult(tr) => ids.contains(tr.call.as_str()),
            _ => false,
        }),
        _ => false,
    }
}

pub(super) fn skill_pair_call_ids_in_history(
    history: &[Message],
) -> std::collections::HashSet<String> {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let mut skill_calls = std::collections::HashSet::new();
    let mut skill_results = std::collections::HashSet::new();
    for msg in history {
        match msg {
            Message::Assistant { content, .. } => {
                for part in content.iter() {
                    if let AssistantContent::ToolCall(tc) = part
                        && is_skill_slash_call_id(tc.id.as_str())
                        && tc.function.name == "skill"
                    {
                        skill_calls.insert(tc.id.to_string());
                    }
                }
            }
            Message::User { content } => {
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part
                        && is_skill_slash_call_id(tr.call.as_str())
                    {
                        skill_results.insert(tr.call.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    skill_calls.intersection(&skill_results).cloned().collect()
}

fn is_skill_slash_call_id(id: &str) -> bool {
    id.starts_with("skillslash-") || id.starts_with("fc-skillslash-")
}

pub(super) fn ensure_or_restore_parked_tool_call(
    history: &mut Vec<Message>,
    payload: &crate::db::needs_attention::InterruptParkPayload,
) -> Result<()> {
    use crate::engine::message::AssistantContent;
    use rig::message::ToolFunction;

    match inspect_unpaired_tool_call(history, &payload.call_id, &payload.tool)? {
        ToolCallAnchorState::Present => Ok(()),
        ToolCallAnchorState::Missing => {
            history.push(Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(
                    crate::engine::message::tool_call_with_identity(
                        payload.call_id.clone(),
                        payload.resume.provider_item_id.clone(),
                        payload.resume.provider_call_id.clone(),
                        ToolFunction {
                            name: payload.tool.clone(),
                            arguments: payload.args.clone(),
                        },
                        None,
                        None,
                    ),
                )],
            });
            Ok(())
        }
    }
}

enum ToolCallAnchorState {
    Present,
    Missing,
}

#[cfg(test)]
mod parked_call_tests {
    use super::*;
    use crate::db::needs_attention::{
        InterruptCallOrigin, InterruptParkPayload, InterruptResumeAnchor,
    };
    use crate::engine::message::AssistantContent;

    #[test]
    fn parked_restore_round_trips_and_reuses_dual_provider_identity() {
        let payload = InterruptParkPayload {
            tool: "bash".to_string(),
            args: serde_json::json!({ "command": "true" }),
            call_id: "cockpit-call-1".to_string(),
            resume: InterruptResumeAnchor {
                agent_id: "Build".to_string(),
                call_id: "cockpit-call-1".to_string(),
                provider_item_id: Some("fc_parked_1".to_string()),
                provider_call_id: Some("call_parked_1".to_string()),
                assistant_seq: Some(7),
                call_origin: InterruptCallOrigin::Foreground,
            },
            gate: None,
        };
        let encoded = serde_json::to_string(&payload).unwrap();
        let restored: InterruptParkPayload = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            restored.resume.provider_item_id.as_deref(),
            Some("fc_parked_1")
        );
        assert_eq!(
            restored.resume.provider_call_id.as_deref(),
            Some("call_parked_1")
        );

        let mut history = Vec::new();
        ensure_or_restore_parked_tool_call(&mut history, &restored).unwrap();
        let Message::Assistant { content, .. } = &history[0] else {
            panic!("parked restore must add an assistant tool call");
        };
        let AssistantContent::ToolCall(call) = &content[0] else {
            panic!("parked restore must add a tool call");
        };
        assert_eq!(call.id, "cockpit-call-1");
        assert_eq!(
            call.provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_parked_1")
        );
        assert_eq!(
            call.provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_parked_1")
        );
    }
}

fn inspect_unpaired_tool_call(
    history: &[Message],
    call_id: &str,
    tool: &str,
) -> Result<ToolCallAnchorState> {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let mut found_call = false;
    let mut found_result = false;
    for msg in history {
        match msg {
            Message::Assistant { content, .. } => {
                for part in content.iter() {
                    if let AssistantContent::ToolCall(tc) = part
                        && tc.id == call_id
                    {
                        if tc.function.name != tool {
                            bail!(
                                "parked call `{call_id}` expected tool `{tool}`, transcript has `{}`",
                                tc.function.name
                            );
                        }
                        found_call = true;
                    }
                }
            }
            Message::User { content } => {
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part
                        && tr.call == call_id
                    {
                        found_result = true;
                    }
                }
            }
            _ => {}
        }
    }
    if !found_call {
        return Ok(ToolCallAnchorState::Missing);
    }
    if found_result {
        bail!("parked call `{call_id}` already has a tool result");
    }
    Ok(ToolCallAnchorState::Present)
}

/// Opening of the cross-agent tool-call attribution note
/// (implementation note). Doubles as the idempotency
/// sentinel: a `tool_result` whose first text part already opens with this was
/// annotated on an earlier message and is left untouched, so re-evaluation on a
/// later send never double-stamps and a re-swap never re-annotates.
const CROSS_AGENT_NOTE: &str = "[Called by `";

/// Return a copy of `tr` with `note` prepended to its first text content part
/// (the model-facing call outcome). Idempotent: if the first text part already
/// opens with [`CROSS_AGENT_NOTE`] the result is returned unchanged. When the
/// result carries no text part (e.g. an image-only result) a fresh leading text
/// part holding the note is inserted, so the attribution is never lost.
pub(super) fn prepend_tool_result_note(
    tr: &rig::message::ToolResult,
    note: &str,
) -> rig::message::ToolResult {
    use rig::message::ToolResultContent;
    let mut parts: Vec<ToolResultContent> = tr.content.to_vec();
    if let Some(idx) = parts
        .iter()
        .position(|p| matches!(p, ToolResultContent::Text(_)))
    {
        if let ToolResultContent::Text(t) = &parts[idx] {
            if t.text.starts_with(CROSS_AGENT_NOTE) {
                return tr.clone();
            }
            let merged = format!("{note}{}", t.text);
            parts[idx] = ToolResultContent::text(merged);
        }
    } else {
        parts.insert(0, ToolResultContent::text(note.to_string()));
    }
    rig::message::ToolResult {
        call: tr.call.clone(),
        provider: tr.provider.clone(),
        name: tr.name.clone(),
        content: parts,
    }
}

/// Compose a noninteractive subagent's brief, injecting the caller's `why`
/// (motivation, GOALS §3c) as a terse leading line so the subagent can tailor
/// what it surfaces/seeds. An empty `why` adds nothing (token economy).
pub(super) fn compose_subagent_brief(brief: &str, why: &str) -> String {
    let why = why.trim();
    if why.is_empty() {
        return brief.to_string();
    }
    format!("[why the caller is asking: {why}]\n\n{brief}")
}

pub(super) fn delegation_payload_reference_prompt(
    row: &crate::db::task_delegation_payloads::TaskDelegationPayloadRow,
) -> String {
    format!(
        "[delegation payload retrieved]\n\
         The exact delegation brief for task `{}` label `{}` was delivered in the immediately \
         preceding `delegation_payload_retrieve` tool result. Treat that retrieved text as the \
         complete task brief and follow it exactly. Payload hash: `{}`.",
        row.task_call_id, row.label, row.payload_hash
    )
}

pub(super) fn delegation_payload_retrieval_history(
    row: &crate::db::task_delegation_payloads::TaskDelegationPayloadRow,
    body: &str,
) -> Vec<Message> {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolFunction, ToolResultContent, UserContent};

    let call_id = delegation_payload_call_id(&row.label, &row.payload_hash);
    vec![
        Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(
                crate::engine::message::tool_call_with_identity(
                    call_id.clone(),
                    None,
                    None,
                    ToolFunction {
                        name: "delegation_payload_retrieve".to_string(),
                        arguments: serde_json::json!({ "hash": row.payload_hash }),
                    },
                    None,
                    None,
                ),
            )],
        },
        Message::User {
            content: vec![UserContent::ToolResult(
                crate::engine::message::tool_result_with_identity(
                    call_id,
                    None,
                    "delegation_payload_retrieve",
                    vec![ToolResultContent::text(body.to_string())],
                ),
            )],
        },
    ]
}

fn delegation_payload_call_id(label: &str, payload_hash: &str) -> String {
    format!("fc-delegation-payload-{}-{}", label, &payload_hash[..12])
}

pub(super) fn extract_todo_delta(report: &str) -> Option<serde_json::Value> {
    let marker = "```todo_delta";
    let start = report.find(marker)?;
    let after = &report[start + marker.len()..];
    let after = after.strip_prefix(" json").unwrap_or(after);
    let after = after.strip_prefix('\n').unwrap_or(after);
    let end = after.find("```")?;
    serde_json::from_str(after[..end].trim()).ok()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(super) struct FilesTouchedReport {
    pub(super) written: Vec<String>,
    pub(super) needs_shared: Vec<String>,
}

pub(super) fn extract_files_touched(report: &str) -> Option<FilesTouchedReport> {
    let marker = "```files_touched";
    let start = report.find(marker)?;
    let after = &report[start + marker.len()..];
    let after = after.strip_prefix(" json").unwrap_or(after);
    let after = after.strip_prefix('\n').unwrap_or(after);
    let end = after.find("```")?;
    serde_json::from_str(after[..end].trim()).ok()
}

#[cfg(test)]
mod files_touched_tests {
    use super::*;

    #[test]
    fn child_report_files_touched_parsed_by_parent() {
        let report = r#"done
```files_touched
{"written":["crates/x/src/a.rs"],"needs_shared":["Cargo.lock"]}
```"#;

        let parsed = extract_files_touched(report).expect("files_touched parsed");
        assert_eq!(
            parsed,
            FilesTouchedReport {
                written: vec!["crates/x/src/a.rs".to_string()],
                needs_shared: vec!["Cargo.lock".to_string()],
            }
        );
        assert!(extract_files_touched("no block").is_none());
        assert!(extract_files_touched("```files_touched\nnot json\n```").is_none());
    }
}

/// Validate a per-delegation tool grant (prompt `parent-granted-tools.md`)
/// against the delegation target's role invariants. Returns `Some(error)` — a
/// clear tool-result string — when the grant is inadmissible, else `None` so
/// the spawn proceeds with the child's surface = base + grants for this run.
///
/// An empty grant is always admissible (the common no-grant case). The `docs`
/// pipeline is a fixed two-stage internal flow whose tool surface is not
/// parent-extensible, so a non-empty grant on it is refused outright. For every
/// other target the grant is checked against the **same** role invariants a
/// user-authored `tools:` grant is ([`crate::agents::invariants::validate_grant`]),
/// resolving the target's own name + mode so the single-writer / spawn-only /
/// primary-only rules are evaluated for that agent. A resolution failure is
/// itself a clear error — the grant is never silently honored.
pub(super) async fn grant_rejection(
    cwd: &std::path::Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    parent_agent: &str,
    child_agent: &str,
    grant: &[String],
    assistant_db: &crate::db::Db,
) -> Option<String> {
    if let Some(message) = crate::engine::builtin::unknown_agent_rejection(
        cwd,
        config,
        parent_agent,
        child_agent,
        assistant_db,
    )
    .await
    {
        return Some(format!("Error: {message}"));
    }
    if grant.is_empty() {
        return None;
    }
    if matches!(child_agent, "docs" | "docs-resolver" | "docs-answerer") {
        return Some(format!(
            "Error: cannot grant tools to `{child_agent}` — the docs pipeline is a fixed \
             internal flow and its tool surface is not extensible."
        ));
    }
    let (target_name, target_mode) = match crate::agents::resolve_with_assistant_db(
        cwd,
        child_agent,
        assistant_db,
    )
    .await
    {
        Ok(Some(def)) => (def.name, def.mode),
        Ok(None) => {
            return Some(format!(
                "Error: cannot grant tools to `{child_agent}` because the agent could not be resolved."
            ));
        }
        Err(e) => {
            return Some(format!(
                "Error: cannot grant tools to `{child_agent}`: {e:#}"
            ));
        }
    };
    match crate::agents::invariants::validate_grant(&target_name, target_mode, grant) {
        Ok(()) => None,
        Err(e) => Some(format!("Error: {e:#}")),
    }
}

/// Produce the shrunk version of a parent history for a delegation
/// (implementation note). `prune` is lossless + sync
/// (snapshot-dedup on a clone); `compact` reuses `compact.rs`'s brief
/// machinery to summarize the (pre-pruned) parent context into a single
/// dense message, with a prune-only fallback on model failure. Runs on the
/// background shrink task, off the parent's frame.
pub(super) async fn run_shrink(
    strategy: crate::config::providers::ShrinkStrategy,
    parent_full: &[Message],
    agent: Arc<Agent>,
    cancel: tokio_util::sync::CancellationToken,
    compact_prompt: Option<String>,
) -> Vec<Message> {
    use crate::config::providers::ShrinkStrategy;
    use crate::engine::deleg_shrink;
    match strategy {
        ShrinkStrategy::Prune => deleg_shrink::prune_shrink(parent_full),
        ShrinkStrategy::Compact => {
            let drafter = deleg_shrink::ModelBriefDrafter {
                agent,
                cancel,
                compact_prompt,
            };
            deleg_shrink::compact_shrink(parent_full, &drafter).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::delegation_payload_call_id;

    #[test]
    fn responses_fc_prefix_mints_are_wire_legal() {
        assert_eq!(
            delegation_payload_call_id("Build", "abcdef1234567890"),
            "fc-delegation-payload-Build-abcdef123456"
        );
    }
}

#[cfg(test)]
mod scoped_write_gate_tests {
    use super::*;
    use crate::engine::schedule::authority::SpawnWorkerKind;
    use crate::write_scope::backend::DirectWorkspaceBackend;

    fn workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();
        tmp
    }

    #[test]
    fn a_write_capable_child_is_refused_on_the_direct_workspace() {
        let ws = workspace();
        let refusal = scoped_write_refusal(
            SpawnWorkerKind::Bee,
            ws.path(),
            "out",
            &DirectWorkspaceBackend,
        )
        .expect("a write-capable child must be refused");
        assert!(refusal.starts_with("refused:"), "{refusal}");
        assert!(
            refusal.contains("hard link"),
            "the refusal should explain why: {refusal}"
        );
        // It offers the two available alternatives rather than dead-ending,
        // and does not claim the alternative is mechanically read-only.
        assert!(refusal.contains("no write tools"), "{refusal}");
        assert!(
            !refusal.contains("read-only"),
            "the refusal must not call a shell-capable worker read-only: {refusal}"
        );
    }

    /// A worker holding no Cockpit write tools receives no transferred
    /// authority, so it is not gated. It is not thereby prevented from writing
    /// via `bash` — see `SpawnWorkerKind::is_write_capable`.
    #[test]
    fn a_worker_without_write_tools_is_unaffected() {
        let ws = workspace();
        assert!(
            scoped_write_refusal(
                SpawnWorkerKind::Scout,
                ws.path(),
                "out",
                &DirectWorkspaceBackend
            )
            .is_none(),
            "a worker with no transferred authority must still dispatch"
        );
    }

    /// A child with no Cockpit write tools receives no transferred authority,
    /// but its `write_scope` still names a real subtree of this workspace. An
    /// escaping scope must never reach scheduling unvalidated just because the
    /// worker holds no write tools.
    #[test]
    fn a_worker_without_write_tools_still_has_its_scope_validated() {
        let ws = workspace();
        for escape in ["../outside", "/etc", ""] {
            let refusal = scoped_write_refusal(
                SpawnWorkerKind::Scout,
                ws.path(),
                escape,
                &DirectWorkspaceBackend,
            )
            .unwrap_or_else(|| {
                panic!("a worker without write tools must still reject scope `{escape}`")
            });
            assert!(
                refusal.contains("not a usable subtree"),
                "`{escape}`: {refusal}"
            );
        }

        // A symlink pointing out of the workspace is resolved, not trusted.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path(), ws.path().join("escape")).unwrap();
            let refusal = scoped_write_refusal(
                SpawnWorkerKind::Scout,
                ws.path(),
                "escape",
                &DirectWorkspaceBackend,
            )
            .expect("a symlink escape must be refused for workers without write tools too");
            assert!(refusal.contains("not a usable subtree"), "{refusal}");
        }
    }

    #[test]
    fn an_escaping_scope_is_reported_as_an_escape_not_a_capability_problem() {
        let ws = workspace();
        for escape in ["../outside", "/etc", ""] {
            let refusal = scoped_write_refusal(
                SpawnWorkerKind::Bee,
                ws.path(),
                escape,
                &DirectWorkspaceBackend,
            )
            .unwrap_or_else(|| panic!("`{escape}` must be refused"));
            assert!(refusal.starts_with("refused:"), "{escape}: {refusal}");
        }
        // The escape message names the scope problem, not the backend.
        let refusal = scoped_write_refusal(
            SpawnWorkerKind::Bee,
            ws.path(),
            "../outside",
            &DirectWorkspaceBackend,
        )
        .unwrap();
        assert!(
            refusal.contains("not a usable subtree"),
            "an escape should be reported as an escape: {refusal}"
        );
    }

    #[test]
    fn the_syntactic_gate_still_requires_a_write_scope() {
        assert!(spawn_gate(0, 4, "").is_err());
        assert!(spawn_gate(0, 4, "   ").is_err());
        let err = spawn_gate(0, 4, "").unwrap_err();
        assert!(err.contains("write_scope"), "{err}");
        // The legacy field name is built at runtime rather than written as a
        // literal: this file is a named spawn anchor, and the rename inventory
        // rejects that literal appearing anywhere inside one.
        let legacy = format!("output{}dir", '_');
        assert!(!err.contains(&legacy), "{err}");
        // Depth ceiling still clamps rather than crashing.
        assert!(spawn_gate(4, 4, "out").is_err());
        assert_eq!(spawn_gate(0, 4, "out").unwrap(), 1);
    }
}

#[cfg(test)]
mod scoped_write_gate_backend_tests {
    use super::*;
    use crate::engine::schedule::authority::SpawnWorkerKind;
    use crate::write_scope::backend::DirectWorkspaceBackend;
    use crate::write_scope::fake::FakeMediatedCowBackend;

    fn workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();
        tmp
    }

    /// The gate must probe the backend it is handed, not a hard-coded one.
    ///
    /// This is what keeps the dispatch-time refusal and the durable transfer in
    /// `run_swarm` in agreement: the driver passes the coordinator's own
    /// backend, so a future Proven backend lights up both at once. If the gate
    /// hard-coded `DirectWorkspaceBackend` again, this test would fail.
    #[test]
    fn the_gate_probes_the_backend_it_is_given() {
        let ws = workspace();

        // Production backend: refused.
        assert!(
            scoped_write_refusal(
                SpawnWorkerKind::Bee,
                ws.path(),
                "out",
                &DirectWorkspaceBackend
            )
            .is_some(),
            "the direct workspace must refuse a write-capable child"
        );

        // A Proven backend: admitted.
        let proven = FakeMediatedCowBackend::new();
        assert!(
            scoped_write_refusal(SpawnWorkerKind::Bee, ws.path(), "out", &proven).is_none(),
            "a Proven backend must admit the same request"
        );

        // Scope validation still applies regardless of backend.
        assert!(
            scoped_write_refusal(SpawnWorkerKind::Bee, ws.path(), "../outside", &proven).is_some(),
            "an escaping scope is refused even on a Proven backend"
        );
    }
}
