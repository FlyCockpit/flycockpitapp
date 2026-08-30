use super::*;

/// One user-invoked skill pair folded into the root history, tracked so a
/// primary swap can strip an abandoned skill the outgoing primary declined
/// to follow (implementation note). The pair is the
/// contiguous assistant(`skill` ToolCall)+user(ToolResult) the seam pushes;
/// both messages carry `call_id` and are removed together so history stays
/// well-formed.
pub(in crate::engine::driver) struct SkillPair {
    /// The synthesized `skill` call's id (the `fc-skillslash-…` value shared by
    /// the assistant ToolCall and its tool_result).
    pub(in crate::engine::driver) call_id: String,
    /// The primary that was active when the skill was invoked. Its swap-out
    /// is what strips the pair.
    pub(in crate::engine::driver) owner: String,
    /// Opt-out seam for a future user-invoked skill that should deliberately
    /// survive a swap and steer the new primary. Always `false` today — no
    /// path sets it — so the scope-narrowly contract ("an *abandoned* skill
    /// must not masquerade as the new primary's instructions") holds without
    /// blocking that future behavior.
    pub(in crate::engine::driver) intentional_steer: bool,
}

impl From<crate::db::skill_pairs::SkillPairRow> for SkillPair {
    fn from(row: crate::db::skill_pairs::SkillPairRow) -> Self {
        Self {
            call_id: row.call_id,
            owner: row.owner,
            intentional_steer: row.intentional_steer,
        }
    }
}

/// A forced-skill load whose only effect so far is reading the skill tool.  It
/// deliberately carries no driver/history/session mutation: oversized user
/// input must finish its durable phase-two composition before the seed becomes
/// observable in any of those places.
pub(in crate::engine::driver) struct PreparedForcedSkill {
    call_id: String,
    skill_name: String,
    args: serde_json::Value,
    body: String,
    hard_fail: bool,
    duration_ms: u64,
    missing_tool: bool,
}

impl PreparedForcedSkill {
    #[cfg(test)]
    pub(in crate::engine::driver) fn envelope_guidance(&self) -> String {
        if self.missing_tool {
            return String::new();
        }
        format!(
            "Skill `{}` (forced, package result):\n\n{}\n\n---\n\n",
            self.skill_name, self.body
        )
    }

    pub(in crate::engine::driver) fn envelope_prelude(&self) -> Option<serde_json::Value> {
        (!self.missing_tool).then(|| {
            serde_json::json!({
                "type": "forced_skill",
                "call_id": self.call_id,
                "name": self.skill_name,
                "args": self.args,
                "body": self.body,
                "hard_fail": self.hard_fail,
            })
        })
    }
}

/// Remove from the root history the user-invoked skill pairs owned by the
/// outgoing primary `owner` that are not flagged `intentional_steer`, so an
/// abandoned skill the outgoing primary declined to follow does not cross a
/// primary swap as authoritative instructions for the new primary
/// (implementation note). Each pair is the
/// contiguous assistant(`skill` ToolCall)+user(ToolResult) the
/// [`Self::seed_forced_skill`] seam pushed; both messages share `call_id`
/// and are removed together so the transcript stays well-formed (no
/// orphaned tool call or unanswered result). The ledger entries for the
/// stripped pairs are dropped; a steering pair (none today) is retained.
impl Driver {
    pub(in crate::engine::driver) async fn strip_abandoned_skill_pairs(&mut self, owner: &str) {
        let ids: std::collections::HashSet<String> = self
            .skill_pairs
            .iter()
            .filter(|p| !p.intentional_steer && p.owner == owner)
            .map(|p| p.call_id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        let history = &mut self.stack[0].history;
        history.retain(|msg| !message_references_call_id(msg, &ids));
        self.skill_pairs
            .retain(|p| p.intentional_steer || p.owner != owner);
        self.delete_persisted_skill_pairs(ids.iter()).await;
    }

    /// Restore the persisted skill-pair ownership ledger after model-history
    /// rehydration. Newer sessions load direct `skill_pairs` rows; older
    /// post-migration resumes can reconstruct from the durable skill-slash
    /// tool-call audit rows because those rows carry both `call_id` and the
    /// agent active when the slash command ran.
    pub(in crate::engine::driver) async fn restore_skill_pairs_after_rehydrate(
        &mut self,
        root_agent: &str,
    ) {
        let present = skill_pair_call_ids_in_history(&self.stack[0].history);
        if present.is_empty() {
            self.skill_pairs.clear();
            return;
        }

        let mut restored: Vec<SkillPair> = self
            .session
            .db
            .list_skill_pairs(self.session.id)
            .await
            .map(|rows| rows.into_iter().map(SkillPair::from).collect())
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "loading skill-pair ownership failed");
                Vec::new()
            });
        restored.retain(|pair| present.contains(&pair.call_id));

        let known: std::collections::HashSet<String> =
            restored.iter().map(|pair| pair.call_id.clone()).collect();
        if known.len() < present.len() {
            let mut inferred = self
                .reconstruct_skill_pairs_from_tool_log(root_agent, &present)
                .await;
            inferred.retain(|pair| !known.contains(&pair.call_id));
            for pair in &inferred {
                if let Err(e) = self
                    .session
                    .db
                    .save_skill_pair(
                        self.session.id,
                        &pair.call_id,
                        &pair.owner,
                        pair.intentional_steer,
                    )
                    .await
                {
                    tracing::warn!(error = %e, call_id = %pair.call_id, "persisting reconstructed skill-pair ownership failed");
                }
            }
            restored.extend(inferred);
        }

        self.skill_pairs = restored;
    }

    pub(in crate::engine::driver) async fn reconstruct_skill_pairs_from_tool_log(
        &self,
        root_agent: &str,
        present: &std::collections::HashSet<String>,
    ) -> Vec<SkillPair> {
        let calls = self
            .session
            .db
            .list_tool_calls_for_session(self.session.id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "loading tool calls for skill-pair reconstruction failed");
                Vec::new()
            });

        let mut pairs = Vec::new();
        for call_id in present {
            let owner = calls
                .iter()
                .find(|call| call.call_id == *call_id && call.tool == "skill")
                .map(|call| call.agent.clone())
                .unwrap_or_else(|| root_agent.to_string());
            pairs.push(SkillPair {
                call_id: call_id.clone(),
                owner,
                intentional_steer: false,
            });
        }
        pairs
    }

    pub(in crate::engine::driver) async fn delete_persisted_skill_pairs<'a, I>(&self, call_ids: I)
    where
        I: IntoIterator<Item = &'a String>,
    {
        let ids: Vec<&str> = call_ids.into_iter().map(String::as_str).collect();
        if ids.is_empty() {
            return;
        }
        if let Err(e) = self
            .session
            .db
            .delete_skill_pairs(self.session.id, ids)
            .await
        {
            tracing::warn!(error = %e, "deleting persisted skill-pair ownership failed");
        }
    }

    pub(in crate::engine::driver) fn expand_skill_tags(
        &self,
        text: &str,
        child_agent: &str,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        let mut seen = std::collections::HashSet::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < text.len() {
            let at_boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r');
            if at_boundary
                && text[i..].starts_with("/skill")
                && text.as_bytes()[i + "/skill".len()..]
                    .first()
                    .is_some_and(u8::is_ascii_whitespace)
            {
                let mut name_start = i + "/skill".len();
                name_start += text[name_start..]
                    .bytes()
                    .take_while(u8::is_ascii_whitespace)
                    .count();
                let name_end = text[name_start..]
                    .find(char::is_whitespace)
                    .map(|offset| name_start + offset)
                    .unwrap_or(text.len());
                let name = &text[name_start..name_end];
                if !name.is_empty() {
                    if seen.insert(name.to_string()) {
                        out.push_str(&self.skill_tag_block(name, child_agent));
                    } else {
                        out.push_str(&format!("[skill {name} already included above]"));
                    }
                    i = name_end;
                    continue;
                }
            }
            let len = text[i..].chars().next().map(char::len_utf8).unwrap_or(1);
            out.push_str(&text[i..i + len]);
            i += len;
        }
        out
    }

    pub(in crate::engine::driver) fn skill_tag_block(
        &self,
        name: &str,
        child_agent: &str,
    ) -> String {
        let name = name.trim();
        if name.is_empty() {
            return String::new();
        }
        match self.active_skills.iter().find(|(n, _)| n == name) {
            Some((name, body)) => format!(
                "We are working on skill `{name}`, and this delegation is part of \
                 resolving it. Its instructions and framing govern what `{child_agent}` \
                 should do for this task — they take precedence over your baked-in \
                 default behavior where they differ (your tool discipline still \
                 holds). Skill `{name}`:\n\n{body}\n\n---\n\n"
            ),
            None => format!("[note: /skill {name} not found]\n\n"),
        }
    }

    /// Synthesize a deterministic `skill` tool call for a user-issued skill
    /// slash command (`/<skill-name>` / `/skill <name>`,
    /// implementation note) and fold it into the foreground
    /// frame's history as a native call/result pair, *before* the first
    /// inference of this turn.
    ///
    /// This is the whole point of the feature (priority #1): a weaker model
    /// may not follow through on a tool call just because a message suggests
    /// one, so the harness invokes the skill itself. It reuses the single
    /// `skill`-tool loading path (`crate::tools::skill::SkillTool`) — body
    /// loading + the frontmatter `model:` override come for free — and the
    /// wire-vs-user transcript machinery: the call is recorded with
    /// `wire_input == original_input` and `Recovery::Clean` (a verbatim
    /// synthesized call, no repair), exactly like a seeded call the caller
    /// made itself. An unknown skill name surfaces the tool's own
    /// `invalid_input` error as the recorded result (never a silent no-op).
    pub(in crate::engine::driver) async fn prepare_forced_skill(
        &self,
        skill_name: &str,
    ) -> PreparedForcedSkill {
        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let Some(tool) = agent.tools.get("skill") else {
            return PreparedForcedSkill {
                call_id: skill_slash_call_id(),
                skill_name: skill_name.to_owned(),
                args: serde_json::json!({ "name": skill_name }),
                body: String::new(),
                hard_fail: true,
                duration_ms: 0,
                missing_tool: true,
            };
        };

        let args = serde_json::json!({ "name": skill_name });
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            allowed_knowledge_bases: if agent.name == "docs-answerer" {
                Some(std::collections::BTreeSet::new())
            } else {
                agent
                    .definition
                    .as_ref()
                    .and_then(crate::agents::AgentDef::allowed_knowledge_bases)
                    .cloned()
            },
            executing_model_trusted: !agent.delegated && agent.model.is_trusted(),
            knowledge_access_trusted: agent.model.is_trusted(),
            caller_model: Some(crate::engine::tool::CallerModel::from_model(
                agent.model.as_ref(),
            )),
            agent_instance_id: None,
            lock_identity: agent.name.clone().clone(),
            write_scope: None,
            dream_read_scope: self.session.dream_read_scope(),
            workspace_lease: None,
            current_tool_call_id: None,
            tool_steering: agent.tool_steering,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: agent.model.shutdown_gate(),
            approver: self.approver.clone(),
            image_generation_dispatch: None,
            transcription_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: Some(self.context_usage_snapshot()),
            available_tools: Arc::new(
                agent
                    .tools
                    .names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            mcp_builtin_registry: agent.tools.mcp_builtin_registry(),
            has_tree: agent.tools.get("code").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Preparation is deliberately silent.  Applying the prepared
            // seed after phase two emits the usual lifecycle events.
            events: None,
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            media_authority: None,
            media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
            config: self.config.clone(),
            env_overlay: agent.env_overlay.clone(),
            mcp_resolver: agent.mcp_resolver.clone(),
        };

        let started = std::time::Instant::now();
        // Forced skills bypass the ordinary tool-timeout dispatcher, but they
        // remain a real production effect boundary. Keep any approval
        // handoff raised by the skill inside the same definitive completion
        // scope rather than letting it escape as an unowned dispatch.
        let result = crate::engine::interrupt::with_host_approval_effect_scope(
            "forced_skill_execution",
            ctx.cancel.clone(),
            tool.call(args.clone(), &ctx),
            |output: &crate::engine::tool::ToolOutput| {
                Some(output.exit_code.is_none_or(|code| code == 0))
            },
        )
        .await;
        let (body, hard_fail) = match result {
            Ok(out) => (out.content.model_text().to_owned(), false),
            // An unknown/ambiguous skill surfaces the tool's invalid-input
            // error as the recorded result — clear, never a silent no-op.
            Err(e) => (format!("Error: {e}"), true),
        };
        let duration_ms = started.elapsed().as_millis() as u64;

        PreparedForcedSkill {
            call_id: skill_slash_call_id(),
            skill_name: skill_name.to_owned(),
            args,
            body,
            hard_fail,
            duration_ms,
            missing_tool: false,
        }
    }

    pub(in crate::engine::driver) async fn seed_forced_skill(
        &mut self,
        skill_name: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let prepared = self.prepare_forced_skill(skill_name).await;
        self.apply_prepared_forced_skill(prepared, tx, true).await;
    }

    /// Apply a previously prepared forced skill.  This is the sole mutation
    /// point for active-skill state, history, tool audit/events and the durable
    /// skill-pair ledger.
    pub(in crate::engine::driver) async fn apply_prepared_forced_skill(
        &mut self,
        prepared: PreparedForcedSkill,
        tx: &mpsc::Sender<TurnEvent>,
        include_history: bool,
    ) {
        use crate::engine::message::{AssistantContent, Message, ToolCall};
        use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

        let PreparedForcedSkill {
            call_id,
            skill_name,
            args,
            body,
            hard_fail,
            duration_ms,
            missing_tool,
        } = prepared;
        if missing_tool {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "skill `{skill_name}` not invoked: this agent has no `skill` tool"
                    ),
                })
                .await;
            return;
        }
        let agent = self.stack.last().expect("stack never empty").agent.clone();
        if !hard_fail {
            let seed_body = body
                .strip_prefix(&format!("Skill `{skill_name}` (package directory: "))
                .and_then(|rest| rest.split_once("):\n\n").map(|(_, body)| body))
                .unwrap_or(&body);
            self.record_active_skill(&skill_name, seed_body);
        }

        let provider_identity = crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
            &call_id,
            Some(agent.model.current_wire_api()),
        );
        let provider_call_id = provider_identity.provider_call_id.clone();
        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                tool: "skill".to_string(),
                args: args.clone(),
            })
            .await;
        let _ = tx
            .send(TurnEvent::ToolEnd {
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                tool: "skill".to_string(),
                output: body.clone(),
                truncated: false,
                seq: None,
                // The hint layer is `bash`-only.
                hint: None,
            })
            .await;

        // Persist the synthesized call as a tool-call audit row + timeline
        // event (GOALS §14), exactly like a call the agent made itself: it is
        // emitted verbatim, so `wire == original` and there is no recovery.
        if let Err(e) = self
            .session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                parent_call_id: None,
                parent_child_index: None,
                identity: provider_identity.clone(),
                tool: "skill".to_string(),
                path: None,
                mcp_server: None,
                original_input_json: args.clone(),
                wire_input_json: args.clone(),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: body.clone(),
                truncated: false,
                duration_ms,
                // Synthesized clean skill-slash call — never goes through §12 repair.
                shape_fingerprint: None,
                // The hint layer is `bash`-only; a skill-slash call never carries one.
                hint: None,
            })
            .await
        {
            tracing::warn!(error = %e, "persisting skill-slash tool_call failed");
        }
        // Host skill-seed, not a model-authored call: `args` is the host-synthesized
        // `{ "name": skill_name }` (built at the top of this fn from the user/host
        // slash-command target, never model free text), and `body`/`output` is the
        // rendered skill package instructions loaded from disk — host content, not
        // model output. `wire == original` because nothing was model-emitted to
        // repair. So this ToolCall payload carries no model-authored session-table
        // literal; frame-less `record_event` is correct (unlike a real agent-emitted
        // tool_call, which tool_dispatch.rs frames). This is the deliberate
        // exception the schedule tool_call is NOT (see schedule_dispatch.rs).
        if let Err(e) = self
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some(&agent.name),
                Some(&call_id),
                &serde_json::json!({
                    "tool": "skill",
                    "original_input": args,
                    "wire_input": args,
                    "recovery_kind": Option::<&str>::None,
                    "recovery_stage": Option::<&str>::None,
                    "hard_fail": hard_fail,
                    "output": body,
                    "truncated": false,
                    "duration_ms": duration_ms,
                    "skill_slash": true,
                    "provider_identity": {
                        "provider_item_id": provider_identity.provider_item_id,
                        "provider_call_id": provider_identity.provider_call_id,
                        "provider_call_id_source": provider_identity.provider_call_id_source,
                        "wire_api": provider_identity.wire_api,
                        "provider_family": provider_identity.provider_family,
                    },
                }),
            )
            .await
        {
            tracing::warn!(error = %e, "recording skill-slash timeline event failed");
        }

        // Fold the call/result into the foreground frame's history as a
        // native pair so the next inference carries the skill body. Pushed as
        // a fresh assistant turn (carrying just this call) followed by its
        // tool_result — well-formed regardless of what preceded it.
        // Preserve one exact Rig correlation handle across the synthesized
        // call/result pair; `call_id` remains available for durable ownership.
        let rig_call_id = rig::message::ToolCallId::new_or_mint(call_id.clone());
        let call = ToolCall {
            id: rig_call_id.clone(),
            provider: (provider_call_id.clone()).and_then(rig::message::ProviderCallId::new),
            function: ToolFunction {
                name: "skill".to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        };
        if include_history {
            let history = &mut self.stack.last_mut().expect("stack never empty").history;
            history.push(Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(call)],
            });
            history.push(Message::User {
                content: vec![UserContent::ToolResult(ToolResult {
                    call: rig_call_id,
                    provider: provider_call_id.and_then(rig::message::ProviderCallId::new),
                    name: "skill".to_string(),
                    content: vec![ToolResultContent::text(body)],
                })],
            });
        }

        // Record ownership so a later primary swap can strip this pair if the
        // owning primary is swapped away without acting on it
        // (implementation note). Only the root frame's
        // primary owns user-invoked skills (slash commands arrive at idle on
        // the root); never set `intentional_steer` today.
        self.skill_pairs.push(SkillPair {
            call_id: call_id.clone(),
            owner: agent.name.clone(),
            intentional_steer: false,
        });
        if let Err(e) = self
            .session
            .db
            .save_skill_pair(self.session.id, &call_id, &agent.name, false)
            .await
        {
            tracing::warn!(error = %e, "persisting skill-pair ownership failed");
        }
    }
}

fn skill_slash_call_id() -> String {
    format!("fc-skillslash-{}", uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::skill_slash_call_id;
    use serde_json::json;

    #[test]
    fn responses_fc_prefix_mints_are_wire_legal() {
        assert!(skill_slash_call_id().starts_with("fc-skillslash-"));
    }

    #[test]
    fn seed_label_output_unchanged_except_escaping() {
        let unchanged = cockpit_host::text::short_args(&json!({ "path": "src/lib.rs" }));
        let unescaped = cockpit_host::text::short_args(&json!({ "name": "say \"hi\"" }));

        assert_eq!(unchanged, "path=\"src/lib.rs\"");
        assert_eq!(unescaped, "name=\"say \"hi\"\"");
        assert!(!unescaped.contains("\\\""));
    }
}
