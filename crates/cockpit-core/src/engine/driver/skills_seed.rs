use super::*;

/// One user-invoked skill pair folded into the root history, tracked so a
/// primary swap can strip an abandoned skill the outgoing primary declined
/// to follow (implementation note). The pair is the
/// contiguous assistant(`skill` ToolCall)+user(ToolResult) the seam pushes;
/// both messages carry `call_id` and are removed together so history stays
/// well-formed.
pub(in crate::engine::driver) struct SkillPair {
    /// The synthesized `skill` call's id (the `skillslash-…` value shared by
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn seed_label_output_unchanged_except_escaping() {
        let unchanged = crate::text::short_args(&json!({ "path": "src/lib.rs" }));
        let unescaped = crate::text::short_args(&json!({ "name": "say \"hi\"" }));

        assert_eq!(unchanged, "path=\"src/lib.rs\"");
        assert_eq!(unescaped, "name=\"say \"hi\"\"");
        assert!(!unescaped.contains("\\\""));
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
    pub(in crate::engine::driver) fn strip_abandoned_skill_pairs(&mut self, owner: &str) {
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
        self.delete_persisted_skill_pairs(ids.iter());
    }

    /// Restore the persisted skill-pair ownership ledger after model-history
    /// rehydration. Newer sessions load direct `skill_pairs` rows; older
    /// post-migration resumes can reconstruct from the durable skill-slash
    /// tool-call audit rows because those rows carry both `call_id` and the
    /// agent active when the slash command ran.
    pub(in crate::engine::driver) fn restore_skill_pairs_after_rehydrate(
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
            .map(|rows| rows.into_iter().map(SkillPair::from).collect())
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "loading skill-pair ownership failed");
                Vec::new()
            });
        restored.retain(|pair| present.contains(&pair.call_id));

        let known: std::collections::HashSet<String> =
            restored.iter().map(|pair| pair.call_id.clone()).collect();
        if known.len() < present.len() {
            let mut inferred = self.reconstruct_skill_pairs_from_tool_log(root_agent, &present);
            inferred.retain(|pair| !known.contains(&pair.call_id));
            for pair in &inferred {
                if let Err(e) = self.session.db.save_skill_pair(
                    self.session.id,
                    &pair.call_id,
                    &pair.owner,
                    pair.intentional_steer,
                ) {
                    tracing::warn!(error = %e, call_id = %pair.call_id, "persisting reconstructed skill-pair ownership failed");
                }
            }
            restored.extend(inferred);
        }

        self.skill_pairs = restored;
    }

    pub(in crate::engine::driver) fn reconstruct_skill_pairs_from_tool_log(
        &self,
        root_agent: &str,
        present: &std::collections::HashSet<String>,
    ) -> Vec<SkillPair> {
        let calls = self
            .session
            .db
            .list_tool_calls_for_session(self.session.id)
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

    pub(in crate::engine::driver) fn delete_persisted_skill_pairs<'a, I>(&self, call_ids: I)
    where
        I: IntoIterator<Item = &'a String>,
    {
        let ids: Vec<&str> = call_ids.into_iter().map(String::as_str).collect();
        if ids.is_empty() {
            return;
        }
        if let Err(e) = self.session.db.delete_skill_pairs(self.session.id, ids) {
            tracing::warn!(error = %e, "deleting persisted skill-pair ownership failed");
        }
    }

    /// Re-execute a `/compact` seed-tool plan into the foreground agent's
    /// initial context, *before* the first inference (T6.e). Each seed is
    /// a read-only / idempotent tool call (`read`, the read-only intel
    /// tools); we dispatch it fresh and fold the results into one
    /// synthetic user message prepended to history — so the fresh agent
    /// starts with the live working set without a round-trip, and never
    /// sees a stale snapshot. Tools the agent doesn't have, or that fail,
    /// are skipped (the brief/appendix still carry the context). A
    /// `ToolStart`/`ToolEnd` pair is emitted per seed so the cost is
    /// visible on the new agent's first turn.
    pub async fn run_seed_tools(
        &mut self,
        seeds: &[crate::db::seed_tools::SeedTool],
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            current_tool_call_id: None,
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            // Seed-tool re-execution runs before the first user turn; it
            // has no run-scoped cancel slot, so a fresh never-cancelled
            // token suffices.
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: agent.model.shutdown_gate(),
            // Seeds are read-only/idempotent and run before the approver
            // is consulted in earnest; a missing approver skips the
            // boundary prompt (never denies).
            approver: self.approver.clone(),
            // Seed re-exec runs read-only tools only; nothing defers or
            // re-seeds.
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
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
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };
        let mut blocks: Vec<String> = Vec::new();
        for seed in seeds {
            // Restrict defensively to read-only/idempotent tools and to
            // tools this agent actually has — never dispatch a write path.
            let Some(tool) = agent.tools.get(&seed.tool) else {
                continue;
            };
            let call_id = format!("seed-{}", uuid::Uuid::new_v4());
            let _ = tx
                .send(TurnEvent::ToolStart {
                    agent: agent.name.clone(),
                    call_id: call_id.clone(),
                    tool: seed.tool.clone(),
                    args: seed.args.clone(),
                })
                .await;
            let result = tool.call(seed.args.clone(), &ctx).await;
            let body = match result {
                Ok(out) => out.content,
                Err(e) => format!("Error: {e}"),
            };
            let _ = tx
                .send(TurnEvent::ToolEnd {
                    agent: agent.name.clone(),
                    call_id,
                    tool: seed.tool.clone(),
                    output: body.clone(),
                    truncated: false,
                    seq: None,
                    // The hint layer is `bash`-only.
                    hint: None,
                })
                .await;
            let label = crate::text::short_args(&seed.args);
            blocks.push(format!(
                "<seed tool=\"{}\" {}>\n{}\n</seed>",
                seed.tool, label, body
            ));
        }
        if !blocks.is_empty() {
            let combined = format!(
                "[compaction handoff — re-executed working-set context; the live results follow]\n\n{}",
                blocks.join("\n\n")
            );
            // Prepend to the first user message rather than pushing a bare
            // user turn (which would put two user messages back-to-back).
            self.pending_seed_context = Some(combined);
        }
    }

    /// Re-execute a list of read-only seeds against `agent`'s toolbox in
    /// `ctx`'s cwd and turn each into a native tool-call/result pair, sharing
    /// one `budget` so the combined output is capped deterministically (whole
    /// seeds dropped once the cap trips — never a half-written record). Both
    /// seed directions reuse this: child→parent ([`Self::inject_seeds`]) runs
    /// it against the **caller**'s agent/cwd and folds the pairs into the
    /// caller's transcript; parent→child ([`Self::prefill_child_seeds`]) runs
    /// it against the **child**'s agent/cwd and prepends the pairs to the
    /// child's initial history.
    ///
    /// Each pair is redaction-scrubbed and persisted as a tool-call audit row
    /// plus a timeline event (GOALS §14), exactly like a call the holder made
    /// itself (verbatim → `wire == original`, no recovery). Seeds naming a tool
    /// the holder doesn't actually hold are skipped (already filtered to
    /// read-only at parse time). A seed whose tool errors in `ctx`'s cwd is a
    /// **failed seed**: its `Error: …` body is injected as the result (so the
    /// holder sees the failure) and counted in the returned failure count —
    /// never a hard abort. When `tx` is `Some`, a `ToolStart`/`ToolEnd` pair is
    /// streamed per injected seed. Returns the native pairs split into the
    /// assistant tool calls and their matching `tool_result` user messages,
    /// plus how many seeds failed to execute.
    #[allow(clippy::type_complexity)]
    pub(in crate::engine::driver) async fn execute_seeds_into_pairs(
        &self,
        seeds: &[crate::db::seed_tools::SeedTool],
        agent: &Agent,
        ctx: &crate::engine::tool::ToolCtx,
        budget: &mut crate::intel::budget::BudgetedWriter,
        tx: Option<&mpsc::Sender<TurnEvent>>,
    ) -> (
        Vec<crate::engine::message::ToolCall>,
        Vec<crate::engine::message::Message>,
        usize,
    ) {
        use crate::engine::message::{Message, OneOrMany, ToolCall};
        use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

        let mut seed_calls: Vec<ToolCall> = Vec::new();
        let mut seed_results: Vec<Message> = Vec::new();
        let mut failed = 0usize;

        for seed in seeds {
            // Restrict to read-only tools the holder actually holds — never
            // dispatch a write path or a tool the holder can't see. (Parse-time
            // filtering already dropped non-read-only entries; this is the
            // hard gate.)
            if !crate::engine::compact::is_read_only_seed_tool(&seed.tool) {
                continue;
            }
            let Some(tool) = agent.tools.get(&seed.tool) else {
                continue;
            };
            let started = std::time::Instant::now();
            let result = tool.call(seed.args.clone(), ctx).await;
            let (body, hard_fail) = match result {
                Ok(out) => (out.content, false),
                // A seed that fails to execute (e.g. the path doesn't exist in
                // this cwd) is surfaced as a failed seed — the error body is
                // injected so the holder sees it — never a hard abort.
                Err(e) => (format!("Error: {e}"), true),
            };
            if hard_fail {
                failed += 1;
            }
            let duration_ms = started.elapsed().as_millis() as u64;
            // Reserve this seed's output against the shared budget. Drop the
            // whole seed (call + result) once the cap is reached.
            if !budget.write(&body) {
                break;
            }
            let call_id = format!("seed-{}", uuid::Uuid::new_v4());
            let provider_identity =
                crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
                    &call_id,
                    Some(agent.model.current_wire_api()),
                );
            let provider_call_id = provider_identity.provider_call_id.clone();
            if let Some(tx) = tx {
                let _ = tx
                    .send(TurnEvent::ToolStart {
                        agent: agent.name.clone(),
                        call_id: call_id.clone(),
                        tool: seed.tool.clone(),
                        args: seed.args.clone(),
                    })
                    .await;
                let _ = tx
                    .send(TurnEvent::ToolEnd {
                        agent: agent.name.clone(),
                        call_id: call_id.clone(),
                        tool: seed.tool.clone(),
                        output: body.clone(),
                        truncated: false,
                        seq: None,
                        // The hint layer is `bash`-only.
                        hint: None,
                    })
                    .await;
            }
            // Persist the seed as a tool-call audit row + timeline event
            // (GOALS §14), exactly like a call the holder made itself: a seed
            // is emitted verbatim, so `wire == original` and there is no
            // recovery. Without this the injected pair would stream to the
            // live client but vanish from a session export.
            if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                parent_call_id: None,
                parent_child_index: None,
                identity: provider_identity.clone(),
                tool: seed.tool.clone(),
                path: None,
                mcp_server: None,
                original_input_json: seed.args.clone(),
                wire_input_json: seed.args.clone(),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: body.clone(),
                truncated: false,
                duration_ms,
                llm_mode: agent.llm_mode,
                // Seed re-exec — not the §12 dispatch path; no repair fingerprint.
                shape_fingerprint: None,
                // The hint layer is `bash`-only; a seed re-exec never carries one.
                hint: None,
            }) {
                tracing::warn!(error = %e, tool = %seed.tool, "persisting seed tool_call failed");
            }
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some(&agent.name),
                Some(&call_id),
                &serde_json::json!({
                    "tool": seed.tool,
                    "original_input": seed.args,
                    "wire_input": seed.args,
                    "recovery_kind": Option::<&str>::None,
                    "recovery_stage": Option::<&str>::None,
                    "hard_fail": hard_fail,
                    "output": body,
                    "truncated": false,
                    "duration_ms": duration_ms,
                    "seed": true,
                    "provider_identity": {
                        "provider_item_id": provider_identity.provider_item_id,
                        "provider_call_id": provider_identity.provider_call_id,
                        "provider_call_id_source": provider_identity.provider_call_id_source,
                        "wire_api": provider_identity.wire_api,
                        "provider_family": provider_identity.provider_family,
                    },
                }),
            ) {
                tracing::warn!(error = %e, "recording seed timeline event failed");
            }
            seed_calls.push(ToolCall {
                id: call_id.clone(),
                call_id: provider_call_id.clone(),
                function: ToolFunction {
                    name: seed.tool.clone(),
                    arguments: seed.args.clone(),
                },
                signature: None,
                additional_params: None,
            });
            seed_results.push(Message::User {
                content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                    id: call_id,
                    call_id: provider_call_id,
                    content: OneOrMany::one(ToolResultContent::text(body)),
                })),
            });
        }

        (seed_calls, seed_results, failed)
    }

    /// Re-execute caller→child read-only pre-seeds (`task.seed`,
    /// implementation note) in the **child**'s cwd and
    /// return native tool-call/result pairs to prepend to the child's initial
    /// history, *before* its first turn. The child therefore starts already
    /// holding the relevant reads instead of re-deriving them. Mirrors
    /// [`Self::inject_seeds`] (the child→parent direction), reusing
    /// [`Self::execute_seeds_into_pairs`]: same read-only gate, same
    /// re-execute-not-replay rule (the seed runs against the child's own
    /// toolbox in the child's cwd), same per-seed budget/drop, and the same
    /// failed-seed-not-abort surfacing.
    ///
    /// Returns the flattened `[assistant tool-calls][matching tool_results]`
    /// history prefix (empty when nothing seeded or nothing survived the
    /// budget) and whether the budget truncated (so the caller can append a
    /// model-visible note to the child's brief).
    pub(in crate::engine::driver) async fn prefill_child_seeds(
        &self,
        seeds: &[crate::db::seed_tools::SeedTool],
        child: &Agent,
        child_cwd: &std::path::Path,
        tx: Option<&mpsc::Sender<TurnEvent>>,
    ) -> (Vec<crate::engine::message::Message>, bool) {
        use crate::engine::message::{AssistantContent, Message, OneOrMany};

        if seeds.is_empty() {
            return (Vec::new(), false);
        }
        // Re-execution against the child's own toolbox and cwd keeps the seed
        // honest (re-execute, never replay the caller's snapshot).
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: child.name.clone(),
            current_tool_call_id: None,
            llm_mode: child.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: child_cwd.to_path_buf(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: child.model.shutdown_gate(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            root_agent_frame: false,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(
                child
                    .tools
                    .names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            mcp_builtin_registry: child.tools.mcp_builtin_registry(),
            has_tree: child.tools.get("tree").is_some(),
            has_bash: child.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: tx.cloned(),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: child.env_overlay.clone(),
        };
        let mut budget = crate::intel::budget::BudgetedWriter::new(SEED_INJECTION_TOKEN_CAP);
        let (seed_calls, seed_results, _failed) = self
            .execute_seeds_into_pairs(seeds, child, &ctx, &mut budget, tx)
            .await;
        if seed_calls.is_empty() {
            return (Vec::new(), budget.is_truncated());
        }
        // One assistant turn carrying all surviving seed calls, followed by
        // their matching tool_results — a well-formed native prefix the child's
        // first inference sees as prior context it already gathered.
        let mut prefix: Vec<Message> = Vec::new();
        if let Ok(content) = OneOrMany::many(
            seed_calls
                .into_iter()
                .map(AssistantContent::ToolCall)
                .collect::<Vec<_>>(),
        ) {
            prefix.push(Message::Assistant { id: None, content });
            prefix.extend(seed_results);
        }
        (prefix, budget.is_truncated())
    }

    /// Inject a re-queryable subagent's seeded read-only results into the
    /// caller's transcript as native tool-call/result pairs (GOALS §3c). Each
    /// seed is **re-executed** in the caller's cwd (never replayed from the
    /// subagent's snapshot), capped under the subagent-report budget via
    /// [`crate::intel::budget::BudgetedWriter`] with a deterministic
    /// truncation note. The seed `ToolCall`s are folded into the SAME
    /// assistant turn that emitted the `task` call — so to the caller they
    /// look like calls it made itself, and the cached prefix is undisturbed —
    /// and their `tool_result`s are pushed before the task call's result.
    ///
    /// Reuses the seed-replay machinery shape from [`Self::run_seed_tools`]:
    /// restricted to tools the caller actually holds, read-only, and
    /// redaction-scrubbed before entering context.
    pub(in crate::engine::driver) async fn inject_seeds(
        &mut self,
        seeds: &[crate::db::seed_tools::SeedTool],
        task_call_id: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        use crate::engine::message::{AssistantContent, Message, OneOrMany};

        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            current_tool_call_id: None,
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: agent.model.shutdown_gate(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
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
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };

        // Token-budget the combined seed output deterministically: one
        // `BudgetedWriter` across all seeds, dropping whole seeds once the cap
        // is reached (atomic, sticky — never a half-written record).
        let mut budget = crate::intel::budget::BudgetedWriter::new(SEED_INJECTION_TOKEN_CAP);
        let (seed_calls, seed_results, _failed) = self
            .execute_seeds_into_pairs(seeds, &agent, &ctx, &mut budget, Some(tx))
            .await;

        if seed_calls.is_empty() {
            return budget.is_truncated();
        }

        // Fold the seed `ToolCall`s into the caller's most recent assistant
        // message (the turn that emitted the `task` call). This keeps them on
        // the same turn the model already produced — cache-safe and native —
        // rather than synthesizing a fresh assistant turn. The matching
        // `tool_result`s are pushed before the task call's result (delivered
        // as `next_prompt`), so every tool call in the turn is answered.
        let history = &mut self.stack.last_mut().expect("stack never empty").history;
        let mut folded = false;
        if let Some(Message::Assistant { content, .. }) = history.last_mut() {
            let has_task_call = content
                .iter()
                .any(|c| matches!(c, AssistantContent::ToolCall(tc) if tc.id == task_call_id));
            if has_task_call {
                let mut parts: Vec<AssistantContent> = content.iter().cloned().collect();
                for call in &seed_calls {
                    parts.push(AssistantContent::ToolCall(call.clone()));
                }
                if let Ok(merged) = OneOrMany::many(parts) {
                    *content = merged;
                    folded = true;
                }
            }
        }
        if !folded {
            // Defensive fallback (the assistant turn wasn't where we expected):
            // push a fresh assistant turn carrying just the seed calls so the
            // pairs are still well-formed.
            if let Ok(content) = OneOrMany::many(
                seed_calls
                    .iter()
                    .cloned()
                    .map(AssistantContent::ToolCall)
                    .collect::<Vec<_>>(),
            ) {
                history.push(Message::Assistant { id: None, content });
            }
        }
        for msg in seed_results {
            history.push(msg);
        }
        budget.is_truncated()
    }

    /// Validate a parent's requested `task.skill_seed` names against the
    /// seedable set ([`Self::active_skills`]) and build the
    /// seeded-skill block to prepend to the child's brief
    /// (implementation note).
    ///
    /// Host-side validation (validate, don't trust the model): a requested name
    /// that is genuinely active (user-invoked OR auto-injected) contributes its
    /// instructions + delegation framing; a name that was never invoked is
    /// **deterministically stripped** and named in a model-visible note so the
    /// child knows the parent's claim of an active skill was dropped — not a
    /// hard error that aborts the delegation. Returns the text to prepend to
    /// the brief (empty when nothing was requested and nothing was stripped).
    ///
    /// The returned block is woven into the child's brief only — it never enters
    /// [`Self::active_skills`] or the root history, so the seeded skill is
    /// scoped to this child's run and does not masquerade as the child's own
    /// user instruction beyond it.
    pub(in crate::engine::driver) fn seed_skills_block(
        &self,
        requested: &[String],
        child_agent: &str,
    ) -> String {
        // De-dup requested names (trim + first-seen order) so a model that
        // names a skill twice doesn't double-inject.
        let mut wanted: Vec<&str> = Vec::new();
        for name in requested {
            let name = name.trim();
            if !name.is_empty() && !wanted.contains(&name) {
                wanted.push(name);
            }
        }
        if wanted.is_empty() {
            return String::new();
        }

        let mut seeded: Vec<(&str, &str)> = Vec::new();
        let mut stripped: Vec<&str> = Vec::new();
        for name in wanted {
            match self.active_skills.iter().find(|(n, _)| n == name) {
                Some((n, body)) => seeded.push((n.as_str(), body.as_str())),
                None => stripped.push(name),
            }
        }

        let mut out = String::new();
        for (name, body) in &seeded {
            out.push_str(&format!(
                "We are working on skill `{name}`, and this delegation is part of \
                 resolving it. Its instructions and framing govern what `{child_agent}` \
                 should do for this task — they take precedence over your baked-in \
                 default behavior where they differ (your tool discipline still \
                 holds). Skill `{name}`:\n\n{body}\n\n---\n\n"
            ));
        }
        if !stripped.is_empty() {
            // Model-visible correction (not a hard error): the parent named
            // a skill that isn't active in its context, so the host dropped it.
            let names = stripped.join("`, `");
            out.push_str(&format!(
                "[note: the seeded skill(s) `{names}` were dropped because they are not \
                 active in the delegating agent's context; only a skill the parent \
                 actually invoked (or that was auto-injected) can be seeded into a \
                 child.]\n\n"
            ));
        }
        out
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
    pub(in crate::engine::driver) async fn seed_forced_skill(
        &mut self,
        skill_name: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        use crate::engine::message::{AssistantContent, Message, OneOrMany, ToolCall};
        use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let Some(tool) = agent.tools.get("skill") else {
            // No `skill` tool on this agent (shouldn't happen for the
            // interactive front-door agents) — surface a notice rather than
            // silently dropping the user's explicit invocation.
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "skill `{skill_name}` not invoked: this agent has no `skill` tool"
                    ),
                })
                .await;
            return;
        };

        let args = serde_json::json!({ "name": skill_name });
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            current_tool_call_id: None,
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: agent.model.shutdown_gate(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
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
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };

        let started = std::time::Instant::now();
        let result = tool.call(args.clone(), &ctx).await;
        let (body, hard_fail) = match result {
            Ok(out) => (out.content, false),
            // An unknown/ambiguous skill surfaces the tool's invalid-input
            // error as the recorded result — clear, never a silent no-op.
            Err(e) => (format!("Error: {e}"), true),
        };
        // Record a successfully-loaded user-invoked skill in the seedable set
        // so a later `task.skill_seed` naming it passes host validation
        // (implementation note). The skill tool's output is
        // `Skill \`name\`:\n\n<rendered body>`; strip that header so the seeded
        // payload carries the instructions, not the wrapper line.
        if !hard_fail {
            let seed_body = body
                .strip_prefix(&format!("Skill `{skill_name}`:\n\n"))
                .unwrap_or(&body);
            self.record_active_skill(skill_name, seed_body);
        }
        let duration_ms = started.elapsed().as_millis() as u64;

        let call_id = format!("skillslash-{}", uuid::Uuid::new_v4());
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
        if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
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
            llm_mode: agent.llm_mode,
            // Synthesized clean skill-slash call — never goes through §12 repair.
            shape_fingerprint: None,
            // The hint layer is `bash`-only; a skill-slash call never carries one.
            hint: None,
        }) {
            tracing::warn!(error = %e, "persisting skill-slash tool_call failed");
        }
        if let Err(e) = self.session.record_event(
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
        ) {
            tracing::warn!(error = %e, "recording skill-slash timeline event failed");
        }

        // Fold the call/result into the foreground frame's history as a
        // native pair so the next inference carries the skill body. Pushed as
        // a fresh assistant turn (carrying just this call) followed by its
        // tool_result — well-formed regardless of what preceded it.
        let call = ToolCall {
            id: call_id.clone(),
            call_id: provider_call_id.clone(),
            function: ToolFunction {
                name: "skill".to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        };
        let history = &mut self.stack.last_mut().expect("stack never empty").history;
        history.push(Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(call)),
        });
        history.push(Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: call_id.clone(),
                call_id: provider_call_id,
                content: OneOrMany::one(ToolResultContent::text(body)),
            })),
        });

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
        if let Err(e) =
            self.session
                .db
                .save_skill_pair(self.session.id, &call_id, &agent.name, false)
        {
            tracing::warn!(error = %e, "persisting skill-pair ownership failed");
        }
    }
}
