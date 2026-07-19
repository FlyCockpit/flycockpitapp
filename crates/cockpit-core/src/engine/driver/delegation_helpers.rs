use super::*;

/// Gate a `spawn` request (GOALS §24): enforce the dedicated-output
/// requirement and the hard depth ceiling (clamp, don't crash). Returns
/// `Ok(child_depth)` (= `parent_depth + 1`) when the spawn is admissible, or
/// `Err(refusal_text)` — the tool result telling the model to do the slice's
/// work itself as a leaf — when `output_dir` is missing or the child would
/// exceed the ceiling. Pure so the gate is unit-testable without a driver.
pub(super) fn spawn_gate(
    parent_depth: u32,
    max_depth: u32,
    output_dir: &str,
) -> std::result::Result<u32, String> {
    if output_dir.trim().is_empty() {
        return Err(
            "refused: `output_dir` is required so concurrent branches don't collide on a file \
             — give this child a dedicated folder/DB path and retry."
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
            content.iter().count() == 1
                && calls.iter().all(|id| ids.contains(*id))
                && !calls.is_empty()
        }
        Message::User { content } => content.iter().any(|c| match c {
            UserContent::ToolResult(tr) => ids.contains(&tr.id),
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
                        && tc.id.starts_with("skillslash-")
                        && tc.function.name == "skill"
                    {
                        skill_calls.insert(tc.id.clone());
                    }
                }
            }
            Message::User { content } => {
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part
                        && tr.id.starts_with("skillslash-")
                    {
                        skill_results.insert(tr.id.clone());
                    }
                }
            }
            _ => {}
        }
    }
    skill_calls.intersection(&skill_results).cloned().collect()
}

pub(super) fn ensure_or_restore_parked_tool_call(
    history: &mut Vec<Message>,
    payload: &crate::db::needs_attention::InterruptParkPayload,
) -> Result<()> {
    use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
    use rig::message::ToolFunction;

    match inspect_unpaired_tool_call(history, &payload.call_id, &payload.tool)? {
        ToolCallAnchorState::Present => Ok(()),
        ToolCallAnchorState::Missing => {
            history.push(Message::Assistant {
                id: None,
                content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                    id: payload.call_id.clone(),
                    call_id: payload.resume.provider_call_id.clone(),
                    function: ToolFunction {
                        name: payload.tool.clone(),
                        arguments: payload.args.clone(),
                    },
                    signature: None,
                    additional_params: None,
                })),
            });
            Ok(())
        }
    }
}

enum ToolCallAnchorState {
    Present,
    Missing,
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
                        && tr.id == call_id
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
    use crate::engine::message::OneOrMany;
    use rig::message::ToolResultContent;
    let mut parts: Vec<ToolResultContent> = tr.content.iter().cloned().collect();
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
        id: tr.id.clone(),
        call_id: tr.call_id.clone(),
        content: OneOrMany::many(parts).unwrap_or_else(|_| tr.content.clone()),
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
    use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
    use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

    let call_id = format!(
        "delegation-payload-{}-{}",
        row.label,
        &row.payload_hash[..12]
    );
    vec![
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.clone(),
                call_id: None,
                function: ToolFunction {
                    name: "delegation_payload_retrieve".to_string(),
                    arguments: serde_json::json!({ "hash": row.payload_hash }),
                },
                signature: None,
                additional_params: None,
            })),
        },
        Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: call_id,
                call_id: None,
                content: OneOrMany::one(ToolResultContent::text(body.to_string())),
            })),
        },
    ]
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
/// primary-only rules are evaluated for that agent. A resolution failure
/// (unknown agent) is itself a clear error — the grant is never silently honored.
pub(super) fn grant_rejection(
    cwd: &std::path::Path,
    child_agent: &str,
    grant: &[String],
) -> Option<String> {
    if grant.is_empty() {
        return None;
    }
    if matches!(child_agent, "docs" | "docs-resolver" | "docs-answerer") {
        return Some(format!(
            "Error: cannot grant tools to `{child_agent}` — the docs pipeline is a fixed \
             internal flow and its tool surface is not extensible."
        ));
    }
    let (target_name, target_mode) = match crate::agents::resolve(cwd, child_agent) {
        Ok(Some(def)) => (def.name, def.mode),
        Ok(None) => {
            return Some(format!(
                "Error: cannot grant tools to unknown agent `{child_agent}`."
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
