use super::*;

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct FailedTurnPromptSummary {
    text: String,
    truncated: bool,
    has_non_text_parts: bool,
}

pub(super) fn prompt_summary(msg: &Message, max_chars: usize) -> FailedTurnPromptSummary {
    let (text, has_non_text_parts) = match msg {
        Message::User { content } => {
            let has_non_text_parts = content
                .iter()
                .any(|part| !matches!(part, rig::message::UserContent::Text(_)));
            (extract_user_text(content), has_non_text_parts)
        }
        Message::Assistant { content, .. } => (extract_text(content), true),
        Message::System { content } => (content.clone(), false),
    };
    let (text, truncated) = crate::text::cap_chars(&text, max_chars);
    FailedTurnPromptSummary {
        text,
        truncated,
        has_non_text_parts,
    }
}

pub(super) fn redacted_bounded_snippet(
    detail: &str,
    redact: &RedactionTable,
    max_chars: usize,
) -> Option<String> {
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::text::bounded_snippet(&redact.scrub(trimmed), max_chars)
}

/// Resolve and build the backup-model fallback for `model`, loading the
/// providers config from the `cwd` config chain
/// (implementation note). The shared seam every turn-runner
/// (the driver loop, noninteractive subagents, the `docs` pipeline) uses so
/// the fallback mechanism is identical everywhere — subagents inherit it, never
/// a hard-coded model. `None` when no backup is configured, the config can't be
/// loaded, or the backup `(provider, model)` can't be built (each ⇒ no
/// fallback / hard-fail, never a crash).
pub(crate) fn resolve_backup_model_for(
    cwd: &std::path::Path,
    model: &crate::engine::model::Model,
) -> Option<Arc<crate::engine::model::Model>> {
    let providers = crate::secret_ref::load_effective(cwd);
    build_backup_model(&providers, model)
}

/// Resolve the per-`(provider, model)` backup against an already-loaded
/// providers config and build it, inheriting `model`'s shutdown gate. Split
/// from [`resolve_backup_model_for`] so the test-injected config path can reuse
/// it without touching disk.
pub(crate) fn build_backup_model(
    providers: &crate::config::providers::ProvidersConfig,
    model: &crate::engine::model::Model,
) -> Option<Arc<crate::engine::model::Model>> {
    let backup = providers.resolve_backup(model.provider_id(), model.model_id_ref())?;
    let built = crate::engine::model::Model::for_provider_trusted_only(
        providers,
        &backup.provider,
        &backup.model,
        // Start from the primary's session redaction table, then let the
        // backup target resolve its own trust policy.
        model.session_redact_table(),
        model.trusted_only_flag(),
    )
    .ok()?;
    let built = built.with_shutdown_gate(model.shutdown_gate());
    // Inherit the primary's wire-API self-heal target so the backup model also
    // pins a corrected endpoint (implementation note).
    let built = match model.config_path() {
        Some(path) => built.with_config_path(path.to_path_buf()),
        None => built,
    };
    Some(Arc::new(built))
}

/// Assemble a finished delegated subagent's report. Every delegated subagent
/// (`builder`/`explore` + custom) holds the structural `return`
/// tool and returns a **structured summary envelope**
/// (implementation note): the model-authored
/// fields (from a `return` call, or — on the fallback path — its final text
/// wrapped as `accomplished`) plus the host-derived `files_changed` ledger from
/// the child's own frame. The `docs` Q&A pipeline is exempt: it holds no
/// `return` tool, so it keeps returning its plain answer unchanged. The
/// subagent's deferred-log section (`plan.md §3d`) is appended either way.
///
/// `return_fields` is `Some` when the subagent finished via the `return` tool;
/// `None` is the no-return-tool fallback (priority #1: a delegation must still
/// yield a valid envelope, never fail).
pub(super) fn assemble_subagent_report(
    agent: &Agent,
    history: &[Message],
    deferred_log: &crate::engine::deferred::DeferredLog,
    return_fields: Option<&serde_json::Value>,
) -> String {
    // Drain the deferred-log once on pop; nothing-deferred is the common path
    // and adds no framing (`plan.md §3d`).
    let deferred_section = if deferred_log.is_empty() {
        String::new()
    } else {
        crate::engine::deferred::format_section(&deferred_log.drain())
    };

    // The `docs` pipeline (and any hypothetical agent without `return`) keeps
    // the legacy plain report. Everything delegated holds `return`.
    if agent.tools.get("return").is_none() {
        return format!("{}{}", collect_final_text(history), deferred_section);
    }

    let envelope = match return_fields {
        Some(fields) => crate::engine::envelope::Envelope::from_return_args(fields),
        None => crate::engine::envelope::Envelope::from_final_text(collect_final_text(history)),
    }
    .with_files_changed(crate::engine::envelope::files_changed_from_history(history));

    format!("{}{}", envelope.render(), deferred_section)
}

pub(super) fn partial_progress_from_history(history: &[Message]) -> DelegationPartialProgress {
    use rig::message::AssistantContent;
    use std::collections::BTreeSet;

    let outputs = partial_progress_tool_outputs(history);
    let mut files_read = BTreeSet::new();
    let mut files_edited = Vec::new();
    let mut commands = Vec::new();
    let mut last_action = None;

    for msg in history {
        let Message::Assistant { content, .. } = msg else {
            continue;
        };
        for part in content.iter() {
            let AssistantContent::ToolCall(tc) = part else {
                continue;
            };
            let tool = tc.function.name.as_str();
            match tool {
                "read" | "readlock" => {
                    if let Some(path) = crate::engine::compact::arg_path(&tc.function.arguments) {
                        files_read.insert(path.clone());
                        last_action = Some(format!("{} `{}`", tool, path));
                    } else {
                        last_action = Some(tool.to_string());
                    }
                }
                "write" | "writeunlock" | "edit" | "editunlock" | "unlock" => {
                    if let Some(path) = crate::engine::compact::arg_path(&tc.function.arguments) {
                        let hash = crate::engine::compact::arg_hash(&tc.function.arguments)
                            .or_else(|| {
                                outputs
                                    .get(&tc.id)
                                    .and_then(|out| crate::engine::compact::hash_from_output(out))
                            });
                        crate::engine::compact::record_edit(&mut files_edited, path.clone(), hash);
                        last_action = Some(format!("{} `{}`", tool, path));
                    } else {
                        last_action = Some(tool.to_string());
                    }
                }
                "bash" => {
                    if let Some(command) = tc
                        .function
                        .arguments
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                    {
                        let command = crate::text::first_line_capped(command, 100);
                        commands.push(PartialProgressCommand {
                            verification: is_verification_command(&command),
                            command: command.clone(),
                        });
                        last_action = Some(format!("bash `{command}`"));
                    } else {
                        last_action = Some("bash".to_string());
                    }
                }
                _ => {
                    last_action = Some(tool.to_string());
                }
            }
        }
    }

    let files_read: Vec<String> = files_read.into_iter().collect();
    let files_edited: Vec<PartialProgressFileEdit> = files_edited
        .into_iter()
        .map(|edit| PartialProgressFileEdit {
            path: edit.path,
            hash: edit.hash,
        })
        .collect();
    let dirty_owned_changes = files_edited
        .iter()
        .map(|edit| edit.path.clone())
        .collect::<Vec<_>>();
    let review_state = if files_edited.is_empty() {
        None
    } else {
        Some("needs_review".to_string())
    };
    let verification_state = if files_edited.is_empty() && commands.is_empty() {
        None
    } else {
        Some("not_completed".to_string())
    };

    DelegationPartialProgress {
        files_read,
        files_edited,
        commands,
        last_action,
        verification_state,
        review_state,
        dirty_owned_changes,
    }
}

fn partial_progress_tool_outputs(history: &[Message]) -> std::collections::HashMap<String, String> {
    use rig::message::{ToolResultContent, UserContent};

    let mut outputs = std::collections::HashMap::new();
    for msg in history {
        let Message::User { content } = msg else {
            continue;
        };
        for part in content.iter() {
            if let UserContent::ToolResult(result) = part {
                let text = result
                    .content
                    .iter()
                    .filter_map(|content| match content {
                        ToolResultContent::Text(text) => Some(text.text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                outputs.insert(result.id.clone(), text);
            }
        }
    }
    outputs
}

pub(super) fn render_failed_subagent_report(
    error_report: &str,
    progress: &DelegationPartialProgress,
) -> String {
    if progress.is_empty() {
        return error_report.to_string();
    }

    let mut out = error_report.trim_end().to_string();
    out.push_str("\n\n## Partial progress (host-derived)\n");
    if let Some(review_state) = &progress.review_state {
        out.push_str(&format!("- Review state: `{review_state}`\n"));
    }
    if let Some(verification_state) = &progress.verification_state {
        if verification_state == "not_completed" {
            out.push_str("- Verification did not complete.\n");
        } else {
            out.push_str(&format!("- Verification state: `{verification_state}`\n"));
        }
    }
    if !progress.files_edited.is_empty() {
        out.push_str("- Files edited:\n");
        for file in &progress.files_edited {
            match &file.hash {
                Some(hash) => out.push_str(&format!("  - `{}` (hash {})\n", file.path, hash)),
                None => out.push_str(&format!("  - `{}`\n", file.path)),
            }
        }
    }
    if !progress.files_read.is_empty() {
        out.push_str("- Files read:\n");
        for file in &progress.files_read {
            out.push_str(&format!("  - `{file}`\n"));
        }
    }
    if !progress.commands.is_empty() {
        out.push_str("- Commands run:\n");
        for command in &progress.commands {
            let suffix = if command.verification {
                " (verification)"
            } else {
                ""
            };
            out.push_str(&format!("  - `{}`{suffix}\n", command.command));
        }
    }
    if let Some(last_action) = &progress.last_action {
        out.push_str(&format!("- Last action: {last_action}\n"));
    }
    if !progress.dirty_owned_changes.is_empty() {
        out.push_str("- Owned changes needing inspection:\n");
        for file in &progress.dirty_owned_changes {
            out.push_str(&format!("  - `{file}`\n"));
        }
    }
    out
}

fn is_verification_command(command: &str) -> bool {
    let command = command.to_ascii_lowercase();
    [
        " test",
        " cargo test",
        "cargo test",
        " check",
        " cargo check",
        "cargo check",
        " clippy",
        " cargo clippy",
        "cargo clippy",
        " fmt --check",
        "cargo fmt --check",
        " build",
        " cargo build",
        "cargo build",
        "pnpm test",
        "npm test",
        "yarn test",
        "pytest",
        "go test",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn collect_final_text(history: &[Message]) -> String {
    // The last assistant message in the history is the subagent's
    // final text. Walk back to find it.
    for msg in history.iter().rev() {
        if let Message::Assistant { content, .. } = msg {
            let text = crate::engine::message::extract_text(content);
            if !text.trim().is_empty() {
                return text;
            }
        }
    }
    String::new()
}
