use super::*;

/// Run a job event as a late-arriving turn in **main** context. A
/// loop-iteration-due event runs the loop's prompt as a real turn (and
/// reports back so the authority schedules the next tick); a terminal
/// completion injects the budget-capped result, then surfaces any
/// fork-emitted spawn requests for the model to decide on.
impl Driver {
    pub(in crate::engine::driver) async fn run_job_event(
        &mut self,
        event: ScheduleEvent,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        match event {
            ScheduleEvent::LoopIterationDue { job_id, prompt } => {
                let framed = format!("[loop {job_id}] {prompt}");
                self.run_user_input(UserSubmission::text(framed), input_rx, tx)
                    .await?;
                // The iteration's turn finished — advance the schedule.
                self.schedule.iteration_finished(&job_id);
            }
            ScheduleEvent::Completed {
                job_id,
                label,
                kind,
                result,
                failed,
                requests,
            } => {
                self.schedule.mark_completed(&job_id);
                // A recursive `Swarm` subagent finished (GOALS §24): free
                // its concurrency slot and start the next queued spawn, before
                // anything else, so the global cap accounting stays tight even
                // if the injected turn below is long-running. Done here on the
                // main thread — the authority is the single scheduler.
                if matches!(kind, crate::engine::schedule::ScheduleKind::Swarm) {
                    self.schedule.swarm_completed();
                }
                // UI marker for the strip / transcript.
                let _ = tx
                    .send(TurnEvent::ScheduleCompleted {
                        job_id: job_id.clone(),
                        label: label.clone(),
                        kind: kind.as_str().to_string(),
                        failed,
                    })
                    .await;
                // Flag the needs-attention queue on every job end (GOALS
                // §22) so a detached client still sees it on reconnect.
                let note = if failed {
                    format!("async {} `{}` failed", kind.as_str(), label)
                } else {
                    format!("async {} `{}` completed", kind.as_str(), label)
                };
                if let Err(e) =
                    self.session
                        .db
                        .raise_interrupt(self.session.id, "schedule", &note, None)
                {
                    tracing::warn!(error = %e, "raising needs_attention on job end failed");
                }
                // Inject the budget-capped result as a late-arriving turn.
                // The header names the originating `job_id` (the same `job-…`
                // string `loop.cancel` / `TurnEvent::ScheduleCompleted` use) so the
                // model has an unambiguous referent — a late delivery may land
                // turns away from its trigger (implementation note).
                let mut injected =
                    format!("{}\n{result}", async_result_header(kind.as_str(), &job_id));
                // Surface any fork-emitted spawn requests (anti-runaway:
                // forks request, main decides). The model sees them and
                // can re-issue a `schedule` call to honour them.
                if !requests.is_empty() {
                    injected.push_str(
                        "\n\nThis loop requested new scheduled work (not started — you decide):",
                    );
                    for req in &requests {
                        injected.push_str(&format!("\n- {}", req.summary()));
                    }
                }
                // Carry the `job_id` on the submission so the recorded
                // `user_message` delivery event stamps `data.job_id`,
                // attributing the delivery to its originating job. The body
                // still flows through `scrub` — redaction stays non-bypassable.
                self.run_user_input(
                    UserSubmission {
                        kind: UserSubmissionKind::User,
                        text: injected,
                        display_text: None,
                        tag_expansions: Vec::new(),
                        images: Vec::new(),
                        forced_skill: None,
                        origin_principal: None,
                        job_id: Some(job_id.clone()),
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    },
                    input_rx,
                    tx,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Dispatch a `schedule` meta-tool action against the authority and return
    /// the tool-result string the model sees. Thin wrapper over
    /// [`Self::dispatch_schedule_action_repaired`] that drops the §14 recovery
    /// surface — the production path ([`TurnOutcome::ScheduleAction`]) needs the
    /// full surface, so this convenience form is used only by tests.
    #[cfg(test)]
    pub(in crate::engine::driver) async fn dispatch_schedule_action(
        &mut self,
        args: &serde_json::Value,
    ) -> Result<String> {
        Ok(self.dispatch_schedule_action_repaired(args).await?.output)
    }

    /// Dispatch a `schedule` meta-tool action, running the §12
    /// validate-then-repair contract on the per-action `args` first, and
    /// return the result text alongside the §14 recovery surface (the
    /// repaired wire `{action, args}` payload + the recovery the row should
    /// record). The single async-job authority lives here on the driver
    /// (GOALS §22), which is why the engine routes `schedule` calls back via
    /// [`TurnOutcome::ScheduleAction`] rather than dispatching them inline.
    ///
    /// The public `schedule` schema and this dispatcher both derive per-action
    /// `args` shapes from [`crate::engine::schedule::schemas`]. We validate the
    /// selected action's `args`, repair on failure through the same
    /// [`crate::engine::repair::repair`] machinery the top-level tool
    /// dispatcher uses, then hand the (possibly-repaired) `args` to the
    /// [`crate::engine::schedule::spec`] parser. A repair that can't validate
    /// falls through to the parser, which produces the same error wording it
    /// does today (out of scope to improve here).
    pub(in crate::engine::driver) async fn dispatch_schedule_action_repaired(
        &mut self,
        args: &serde_json::Value,
    ) -> Result<ScheduleDispatch> {
        use crate::engine::repair::repair;
        use crate::engine::schedule::schemas::schema_for;
        use crate::tools::schedule::split_action;

        let (action, mut action_args) = split_action(args)?;

        // Per-action validate → repair → re-validate (§12), keyed by the
        // selected action's schema. A clean call is byte-identical; a
        // repairable malformation (e.g. `limit:"1"`) is coerced; an
        // unrecoverable call still flows to the parser below (same error).
        let schema = schema_for(action);
        let recovery = repair(&mut action_args, &schema, "schedule").recovery;

        // The §14 wire payload reflects the repaired sub-args so the audit
        // row's `wire_input` shows the canonical form the parser consumed.
        let wire_args = serde_json::json!({
            "action": action.as_str(),
            "args": action_args.clone(),
        });

        let output = self.run_job_action(action, &action_args).await?;
        Ok(ScheduleDispatch {
            output,
            recovery,
            wire_args,
        })
    }

    /// Execute a `schedule` action against the authority with already-validated,
    /// repaired per-action `action_args`, returning the model-facing result
    /// text. Split out of [`Self::dispatch_schedule_action_repaired`] so the
    /// repair pass owns the §14 surface and this method owns the dispatch.
    pub(in crate::engine::driver) async fn run_job_action(
        &mut self,
        action: crate::engine::schedule::ScheduleAction,
        action_args: &serde_json::Value,
    ) -> Result<String> {
        use crate::engine::schedule::{ScheduleAction, ScheduleKind};

        match action {
            ScheduleAction::LoopStart => {
                if self.schedule.at_capacity() {
                    anyhow::bail!(
                        "max concurrent scheduled tasks reached ({}); cancel one before starting another",
                        self.schedule.max_concurrent
                    );
                }
                let parsed = crate::engine::schedule::parse_loop_start(action_args)?;
                let kind = parsed.kind();
                let limit = parsed.limit;
                let limit_defaulted = parsed.limit_defaulted;
                if limit.is_none() {
                    self.ensure_unbounded_loop_allowed().await?;
                }
                let job_id = if parsed.keep_in_context {
                    self.schedule.start_loop_in_context(parsed)
                } else {
                    self.schedule.start_loop_forked(parsed)
                };
                let noun = if kind == ScheduleKind::Timer {
                    "timer"
                } else {
                    "loop"
                };
                Ok(crate::engine::schedule::loop_start_message(
                    noun,
                    &job_id,
                    limit,
                    limit_defaulted,
                ))
            }
            ScheduleAction::LoopCancel => {
                let parsed = crate::engine::schedule::parse_loop_cancel(action_args)?;
                if self.schedule.cancel(&parsed.job_id) {
                    Ok(format!("cancelled `{}`", parsed.job_id))
                } else {
                    Ok(format!("no live job `{}`", parsed.job_id))
                }
            }
            ScheduleAction::BackgroundStart => {
                if self.schedule.at_capacity() {
                    anyhow::bail!(
                        "max concurrent scheduled tasks reached ({}); cancel one before starting another",
                        self.schedule.max_concurrent
                    );
                }
                let parsed = crate::engine::schedule::parse_background_start(action_args)?;
                let job_id = self.schedule.start_background(parsed);
                Ok(format!(
                    "started background `{job_id}` — tail with schedule(action=\"background.tail\", args={{\"job_id\":\"{job_id}\"}})"
                ))
            }
            ScheduleAction::BackgroundTail => {
                let parsed = crate::engine::schedule::parse_background_tail(action_args)?;
                match self.schedule.background_handle(&parsed.job_id) {
                    Some(handle) => Ok(handle.tail(parsed.lines, &self.redact)),
                    None => Ok(format!("no live background `{}`", parsed.job_id)),
                }
            }
            ScheduleAction::BackgroundCancel => {
                let parsed = crate::engine::schedule::parse_background_cancel(action_args)?;
                if self.schedule.cancel(&parsed.job_id) {
                    Ok(format!("cancelled background `{}`", parsed.job_id))
                } else {
                    Ok(format!("no live background `{}`", parsed.job_id))
                }
            }
            ScheduleAction::List => {
                let snap = self.schedule.snapshot();
                let running_swarm = self.schedule.running_swarm();
                let queued_swarm = self.schedule.queued_swarm();
                let scheduled: Vec<serde_json::Value> = snap
                    .into_iter()
                    .map(|j| {
                        serde_json::json!({
                            "job_id": j.job_id,
                            "kind": j.kind.as_str(),
                            "label": j.label,
                            "status": j.status.as_str(),
                            "executions_completed": j.iteration,
                            "execution_limit": j.limit,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "scheduled": scheduled,
                    "swarm": {
                        "running": running_swarm,
                        "queued": queued_swarm,
                    }
                })
                .to_string())
            }
        }
    }

    pub(in crate::engine::driver) fn record_schedule_tool_call(&self, row: ScheduleToolCallRecord) {
        // A `schedule` action is dispatched to the main-thread authority, not
        // through the ordinary tool-dispatch path, so — unlike every other tool
        // — it never wrote a `tool_call` row to the export timeline; the export
        // (which reads `session_events`) showed only failed bash/mcp detours,
        // never the successful native call (implementation note,
        // §5). Mirror the ordinary-tool pattern: persist BOTH the
        // `tool_call_events` row (`/stats`, history) AND a `tool_call`
        // `session_events` row (the export's dispatch record).
        let (recovery_kind, recovery_stage) = row.recovery.db_fields();
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some(&row.agent),
            Some(&row.call_id),
            &serde_json::json!({
                "tool": "schedule",
                "original_input": row.original_input_json,
                "wire_input": row.wire_input_json,
                "recovery_kind": recovery_kind,
                "recovery_stage": recovery_stage,
                "hard_fail": row.hard_fail,
                "output": row.output,
                "truncated": false,
                "duration_ms": row.duration_ms,
            }),
        ) {
            tracing::warn!(error = %e, "recording schedule timeline event failed");
        }
        if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: row.agent,
            call_id: row.call_id,
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "schedule".to_string(),
            path: None,
            mcp_server: None,
            original_input_json: row.original_input_json,
            wire_input_json: row.wire_input_json,
            recovery: row.recovery,
            hard_fail: row.hard_fail,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: row.output,
            truncated: false,
            duration_ms: row.duration_ms,
            llm_mode: row.llm_mode,
            // The schedule meta-tool's fixed minimal-schema repair fingerprint is not
            // threaded through `ScheduleToolCallRecord`; the §12 fingerprint telemetry
            // covers the per-tool dispatch path.
            shape_fingerprint: None,
            // The hint layer is `bash`-only; a `schedule` call never carries one.
            hint: None,
        }) {
            tracing::warn!(error = %e, "persisting schedule tool_call_event failed");
        }
    }
}
