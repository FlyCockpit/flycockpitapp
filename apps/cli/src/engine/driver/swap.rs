use super::*;

/// Switch the active model+provider live (`mid-session-model-
/// switch.md`), at the idle control boundary like every other primary swap.
/// Builds the new [`Model`](crate::engine::model::Model) for
/// `(provider, model)` from the layered config, threading the session's
/// effective redaction table (`self.redact`) so the new model keeps the
/// non-bypassable scrub chokepoint (GOALS §7), and inheriting the current
/// model's shutdown gate + wire-API self-heal target. On success it rebuilds
/// the **root primary** under the new model — preserving the root history so
/// the same conversation continues — persists the session's active-model row,
/// and refreshes the prunable projection. On any failure (provider not
/// configured, bad id, missing credentials) it **fails loudly** via a
/// [`TurnEvent::Notice`] and leaves the current model active (no silent
/// no-op, no crash). The prompt-cache break is expected and accepted.
impl Driver {
    pub(in crate::engine::driver) async fn set_active_model_live(
        &mut self,
        provider: &str,
        model: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        // A no-op when the requested model is already the active one — never
        // rebuild (and bust the cache) for a same-model re-select.
        let active_idx = self.stack.len().saturating_sub(1);
        let current = &self.stack[active_idx].agent.model;
        if current.provider_id() == provider && current.model_id_ref() == model {
            return;
        }
        // The new model inherits the running model's shutdown gate (so a daemon
        // drain still refuses its dispatch) and wire-API self-heal target.
        let new_model = match self.build_live_model(provider, model) {
            Ok(m) => Arc::new(m),
            Err(e) => {
                // Fail loudly, keep the current model active.
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Model switch to `{provider}/{model}` failed — {e:#}. \
                             Keeping the current model active."
                        ),
                    })
                    .await;
                return;
            }
        };
        let rebuilt = self.rebuild_frame_with_model(active_idx, new_model);
        self.stack[active_idx].agent = Arc::new(rebuilt);
        if active_idx == 0 {
            // The job authority's fork context is rooted on the root agent;
            // rebind it when the root model changes.
            self.schedule.set_agent(self.stack[0].agent.clone());
            if let Err(e) = self.session.set_active_model(provider, model) {
                tracing::warn!(error = %e, "persisting active model after live switch failed");
            }
        }
        tracing::info!(provider, model, "active model switched live");
        // The model changed, so the prefix cache key changes — refresh the
        // prunable projection the chrome shows (cache-cold reflects the bust).
        self.emit_context_projection(tx).await;
    }

    /// Build a fresh [`Model`](crate::engine::model::Model) for `(provider,
    /// model)` from the layered config (honoring the test-injected config in
    /// tests), threading the session's effective redaction table and inheriting
    /// the running model's shutdown gate + wire-API self-heal target. The new
    /// model's reasoning params are re-resolved from the config's active-model
    /// thinking mode and ride on the rebuilt root agent (see
    /// [`Self::rebuild_root_with_model`]). Errors propagate so the caller can
    /// surface them (unconfigured provider / bad id / missing key).
    pub(in crate::engine::driver) fn build_live_model(
        &self,
        provider: &str,
        model: &str,
    ) -> Result<crate::engine::model::Model> {
        let providers = self.live_providers_config()?;
        let running = &self.stack.last().expect("stack never empty").agent.model;
        let env_overlay = self.stack[0].agent.env_overlay.clone();
        let built = crate::engine::model::Model::for_provider_with_env_trusted_only(
            &providers,
            provider,
            model,
            self.redact.clone(),
            running.trusted_only_flag(),
            move |name| {
                env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(name)
                    .cloned()
            },
        )?
        .with_shutdown_gate(running.shutdown_gate());
        let built = match running.config_path() {
            Some(path) => built.with_config_path(path.to_path_buf()),
            None => built,
        };
        Ok(built)
    }

    /// Swap the root-frame agent to `name` in place, preserving the root
    /// history so the new primary continues the same conversation. Only the
    /// root frame is swapped, and only at idle (the control boundary) — a
    /// deeper interactive subagent frame is never touched. No-op when an
    /// interactive subagent holds the foreground or the agent is already
    /// active. The new agent is built through [`crate::engine::builtin::load`]
    /// so a user override of `Plan`/`Build` takes effect.
    ///
    /// Before re-rooting, the outgoing primary's abandoned (non-steering)
    /// user-invoked skill pairs are stripped from history so a skill the
    /// previous primary declined to follow does not govern the new primary
    /// (implementation note).
    ///
    /// The imperative-kickoff contract (begin work on the first turn, tool
    /// call not narration) attaches only to the [`Self::apply_handoff`] path:
    /// a `handoff` fires **mid-turn**, so the swapped-in primary's first input
    /// is the synthesized `handoff` tool_result, which `apply_handoff` builds
    /// as the kickoff. The `/plan`/`/build`/`/swarm` (and `/agent`,
    /// `Shift+Tab`) swaps route here at **idle** and return to idle without a
    /// turn — the new primary's first turn is driven by the user's *next*
    /// message, which is already actionable, so there is no separate kickoff
    /// to inject for those paths.
    pub(in crate::engine::driver) async fn swap_primary(
        &mut self,
        name: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        self.swap_primary_with_context(name, PrimarySwapContext::swap_command(), tx)
            .await;
    }

    /// [`Self::swap_primary`] plus the export-audit `primary_swap` context: the
    /// trigger and (for the `handoff` path) the wire-vs-user `display`/`kickoff`
    /// pair (GOALS §14). The control-swap entry point passes
    /// [`PrimarySwapContext::swap_command`] (no kickoff); [`Self::apply_handoff`]
    /// passes the handoff display + kickoff. The `primary_swap` timeline event
    /// is recorded only on a successful re-root, so a failed agent load never
    /// records a phantom swap.
    pub(in crate::engine::driver) async fn swap_primary_with_context(
        &mut self,
        name: &str,
        swap_ctx: PrimarySwapContext<'_>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if self.stack.len() != 1 {
            tracing::warn!(
                requested = %name,
                "primary swap ignored: an interactive subagent holds the foreground"
            );
            return false;
        }
        if self.stack[0].agent.name == name {
            return true;
        }
        match crate::engine::builtin::load(name, &self.spawn_args(true)) {
            Ok(agent) => {
                // An abandoned skill the outgoing primary declined to follow
                // must not cross the swap as authoritative instructions for
                // the new primary (implementation note).
                // Strip the outgoing primary's non-steering skill pairs before
                // re-rooting; a future intentionally-steering skill opts out
                // via `intentional_steer` and survives.
                let outgoing = self.stack[0].agent.name.clone();
                self.strip_abandoned_skill_pairs(&outgoing);
                // Per-call tool-call ownership (`cross-agent-tool-call-
                // annotation.md`): attribute every not-yet-attributed tool call
                // now in the root history to the OUTGOING agent before re-
                // rooting. Runs AFTER the skill-pair strip so an abandoned skill
                // call (already removed) is never attributed. Swaps fire at idle,
                // so the just-finished run's calls are all present — attribution
                // is exact across any number of swaps. Existing entries are never
                // overwritten (a re-swap doesn't reattribute earlier calls).
                self.record_tool_call_ownership(&outgoing);
                let outgoing_write_capable =
                    crate::engine::builtin::is_write_capable(&self.stack[0].agent);
                let incoming_write_capable = crate::engine::builtin::is_write_capable(&agent);
                if outgoing_write_capable {
                    let lock_result = if incoming_write_capable {
                        self.locks
                            .transfer_agent_locks(&outgoing, &agent.name, self.session.id)
                            .map(|_| ())
                    } else {
                        self.locks
                            .suspend_agent(&outgoing, self.session.id)
                            .map(|_| ())
                    };
                    if let Err(e) = lock_result {
                        tracing::warn!(
                            error = ?e,
                            from = %outgoing,
                            to = %agent.name,
                            "primary swap failed during lock ownership update"
                        );
                        return false;
                    }
                }
                // Deferred agent-swap identity marker (`agent-swap-
                // identity-marker.md`): a `swap_command` swap leaves no boundary
                // entry on the wire, so record the previously-effective agent now
                // for injection on the user's next message. Capture the outgoing
                // agent only at the FIRST swap since the last message — never
                // overwrite it on an intermediate hop — so a multi-swap run
                // coalesces to one marker naming previously-effective → final.
                // The `handoff` path injects its own kickoff and sets nothing.
                if swap_ctx.trigger == SWAP_TRIGGER_COMMAND
                    && self.pending_swap_marker_from.is_none()
                {
                    self.pending_swap_marker_from = Some(outgoing.clone());
                }
                self.stack[0].agent = Arc::new(agent);
                self.stack[0].queue_target =
                    crate::engine::message::QueueTarget::root(name.to_string());
                // The job authority's fork context is rooted on the old
                // agent; rebind it so any future loop fork runs on the new
                // primary's model/tool surface (single-authority rule).
                self.schedule.set_agent(self.stack[0].agent.clone());
                tracing::info!(agent = %name, "primary agent swapped");
                // `primary_swap` timeline event (export-audit fidelity):
                // from/to + trigger + both halves of the wire-vs-user split.
                if let Err(e) = self.session.record_primary_swap(
                    &outgoing,
                    name,
                    swap_ctx.trigger,
                    swap_ctx.display,
                    swap_ctx.kickoff,
                ) {
                    tracing::warn!(error = %e, "record primary_swap event failed");
                }
                // Tell the client chrome's active-agent slot about the new
                // primary, then refresh the prunable projection.
                let _ = tx
                    .send(TurnEvent::PrimarySwapped {
                        name: name.to_string(),
                    })
                    .await;
                let _ = tx
                    .send(TurnEvent::ForegroundInputTarget {
                        target: self.active_queue_target(),
                    })
                    .await;
                self.emit_context_projection(tx).await;
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, requested = %name, "primary swap failed to load agent");
                false
            }
        }
    }

    /// Build the imperative kickoff the swapped-in primary takes its first
    /// turn on after a `handoff` (implementation note).
    /// It restates the user's **salient originating request verbatim** (the
    /// most recent user turn in the shared root history — not the outgoing
    /// primary's paraphrase) and instructs the new primary to begin now with a
    /// tool call rather than a description of intent. This replaces the bare
    /// `` "Handed off to `{target}`." `` ack — a weaker model reads that ack as
    /// something to narrate and emits no tool call, terminating the loop.
    /// Token-efficient (§10): the restated request plus one imperative line,
    /// no boilerplate. Falls back to the imperative alone when no user turn is
    /// present (defensive — a handoff always follows a user request).
    pub(in crate::engine::driver) fn handoff_kickoff(&self) -> String {
        let request = crate::engine::predict::turns_from_messages(&self.stack[0].history)
            .pop()
            .map(|t| t.user)
            .filter(|u| !u.trim().is_empty());
        let imperative = "Begin now. Act on this request directly — your first action must be a \
                          tool call, not a description of what you intend to do.";
        match request {
            Some(req) => format!("User's request:\n{}\n\n{imperative}", req.trim()),
            None => imperative.to_string(),
        }
    }

    /// Annotate, in the wire history, every historical tool call whose tool the
    /// **final** (now-active) agent lacks
    /// (implementation note). Consumed at the user's
    /// next message — the same coalesce-and-defer boundary as
    /// [`Self::inject_pending_swap_marker`] — so the cached prefix stays
    /// byte-stable until the message is actually sent, and absence is evaluated
    /// once against the final agent's authoritative tool set
    /// ([`crate::engine::tool::ToolBox::get`], role-driven, not name-bound).
    ///
    /// For each matching call the note is prepended to its `tool_result`
    /// content (what the model reads as the call's outcome), e.g.
    /// `` [Called by `Build`, which had the `edit` tool. You (`Plan`) do not ``
    /// `` have this tool.] ``. Calls for tools the final agent still has are
    /// left unchanged; `task` (subagent) calls follow the same rule. Wire-only
    /// (GOALS §14) — the user transcript is untouched.
    ///
    /// Idempotent: an already-annotated result (carrying [`CROSS_AGENT_NOTE`])
    /// is skipped, so re-evaluation on a later message never double-stamps, and
    /// a re-swap that restores the tool never strips an earlier note (it stays
    /// historically accurate). Only meaningful at the root frame.
    pub(in crate::engine::driver) fn annotate_absent_tool_calls(&mut self) {
        use crate::engine::message::{AssistantContent, OneOrMany};
        use rig::message::UserContent;
        if self.tool_call_owner.is_empty() {
            return;
        }
        let final_agent = self.active_agent().to_string();
        let root = &self.stack[0];
        // call_id → tool name, for every tool call in the root history, plus
        // the set of tool names absent from the final agent's authoritative
        // surface (`ToolBox::get`, role-driven). Built up front so the history
        // mutation below borrows nothing else from `self`.
        let mut absent_call: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for msg in &root.history {
            if let Message::Assistant { content, .. } = msg {
                for c in content.iter() {
                    if let AssistantContent::ToolCall(tc) = c
                        && root.agent.tools.get(&tc.function.name).is_none()
                    {
                        absent_call.insert(tc.id.clone(), tc.function.name.clone());
                    }
                }
            }
        }
        if absent_call.is_empty() {
            return;
        }
        let owners = &self.tool_call_owner;
        for msg in &mut self.stack[0].history {
            let Message::User { content } = msg else {
                continue;
            };
            // Skip well-formed messages with no annotatable tool_result fast.
            if !content.iter().any(
                |p| matches!(p, UserContent::ToolResult(tr) if absent_call.contains_key(&tr.id)),
            ) {
                continue;
            }
            let parts: Vec<UserContent> = content
                .iter()
                .map(|part| match part {
                    UserContent::ToolResult(tr) => {
                        let (Some(tool), Some(owner)) =
                            (absent_call.get(&tr.id), owners.get(&tr.id))
                        else {
                            return part.clone();
                        };
                        let note = format!(
                            "[Called by `{owner}`, which had the `{tool}` tool. You \
                             (`{final_agent}`) do not have this tool.] "
                        );
                        UserContent::ToolResult(prepend_tool_result_note(tr, &note))
                    }
                    other => other.clone(),
                })
                .collect();
            if let Ok(rebuilt) = OneOrMany::many(parts) {
                *content = rebuilt;
            }
        }
    }

    /// Apply an `Auto` → `Plan`/`Build` handoff at the idle boundary and
    /// return the `handoff` tool_result the swapped-in primary takes its next
    /// turn on. Emits the `handoff` tool_call timeline events, persists the
    /// new active agent (so a resume restarts on it), then swaps the
    /// root-frame primary in place through [`Self::swap_primary`] — the same
    /// machinery `/plan`/`/build` use, which preserves the root history so the
    /// chosen primary continues this same conversation. Sole owner of the
    /// handoff side effects so the live turn loop and the regression test
    /// drive byte-identical behavior. The tool_result is built **before** the
    /// swap so it lands in the shared root history `swap_primary` preserves.
    ///
    /// The tool_result the swapped-in primary takes its first turn on is the
    /// **imperative kickoff** ([`Self::handoff_kickoff`]) — the user's salient
    /// originating request restated verbatim plus a begin-now instruction —
    /// **not** a bare ack. A bare ack made weaker models narrate and emit no
    /// tool call, terminating the loop (`handoff-kickoff-and-skill-
    /// leak.md`). The **user-facing** timeline still shows the terse
    /// `` "Handed off to `{target}`." `` row (wire-vs-user split, GOALS §14):
    /// the model sees the kickoff (wire), the user sees the clean ack.
    pub(in crate::engine::driver) async fn apply_handoff(
        &mut self,
        target: &str,
        task_call_id: String,
        task_function_call_id: Option<String>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Message {
        let agent_name = self.stack.last().unwrap().agent.name.clone();
        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                args: serde_json::json!({ "target": target }),
            })
            .await;
        // User-facing timeline row: terse ack. The model-facing tool_result is
        // the imperative kickoff (wire-vs-user split, GOALS §14).
        let display = format!("Handed off to `{target}`.");
        let _ = tx
            .send(TurnEvent::ToolEnd {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                output: display.clone(),
                truncated: false,
                // The hint layer is `bash`-only.
                hint: None,
            })
            .await;
        // Build the kickoff from the user's originating request BEFORE the swap
        // strips any abandoned skill pair — `turns_from_messages` reads the
        // last plain user turn (the skill body is a tool-result round it skips),
        // so the restated request is the user's, not the skill's.
        let kickoff = self.handoff_kickoff();
        let next_prompt =
            Message::tool_result_with_call_id(task_call_id, task_function_call_id, kickoff.clone());
        // The `primary_swap` event records BOTH the user-facing `display` and
        // the model-facing wire `kickoff` (GOALS §14) with trigger `handoff`.
        let swapped = self
            .swap_primary_with_context(target, PrimarySwapContext::handoff(&display, &kickoff), tx)
            .await;
        if swapped && let Err(e) = self.session.set_active_agent(target) {
            tracing::warn!(error = %e, "set_active_agent on handoff failed");
        }
        next_prompt
    }
}
