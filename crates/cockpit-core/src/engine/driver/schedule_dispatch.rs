use super::*;

pub(in crate::engine::driver) fn scheduled_job_submission(
    text: String,
    job_id: Option<String>,
) -> UserSubmission {
    let mut submission = UserSubmission::text(text);
    submission.origin = crate::engine::message::SubmissionOrigin::ScheduledJob;
    submission.job_id = job_id;
    submission
}

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
                if self.persist_on_reentry_owns_started_unsettled_siblings() {
                    // Do not run the tick or call `iteration_finished`: keep-park
                    // `run_user_input` Ok is not a completed iteration. The idle
                    // fence must not recv this event until persist-on-re-entry
                    // releases; reaching here is fail-closed.
                    anyhow::bail!(
                        "persist-on-re-entry owns started-unsettled keep-parked siblings"
                    );
                }
                let framed = format!("[loop {job_id}] {prompt}");
                self.run_user_input(scheduled_job_submission(framed, None), input_rx, tx)
                    .await?;
                // The iteration's turn finished — advance the schedule.
                self.schedule.iteration_finished(&job_id);
            }
            ScheduleEvent::SwarmChildStarted {
                job_id,
                subagent_type,
            } => {
                // A genuine detached-`Swarm` child (`bee` / `scout`) started
                // (spawn mode 3 of 3). Fire `subagentStart` and track it so the
                // paired `subagentStop` fires when its `Completed` is drained.
                // The authority never emits this for goal-supervision workers
                // (guidance L22), so this boundary is child-only by construction.
                self.fire_swarm_subagent_start(&job_id, &subagent_type)
                    .await;
            }
            ScheduleEvent::SwarmChildStopGateCompleted { job_id } => {
                // A genuine detached-`Swarm` child ran its own controlling
                // `subagentStop` gate inside `run_swarm_loop` before publishing
                // its terminal result. Mark it so the paired `Completed` drain
                // does not fire a second (terminal) `subagentStop`. FIFO: this
                // ordered marker is always drained before that job's `Completed`.
                self.mark_swarm_subagent_stop_gate_completed(&job_id);
            }
            ScheduleEvent::Completed {
                job_id,
                label,
                kind,
                result,
                failed,
                requests,
            } => {
                if self.persist_on_reentry_owns_started_unsettled_siblings() {
                    // Do not `mark_completed` or inject: keep-park `Ok(())`
                    // would drop the body (empty queue_item_ids, no requeue)
                    // after the row was already removed. The idle fence must
                    // not recv this event until persist-on-re-entry releases.
                    anyhow::bail!(
                        "persist-on-re-entry owns started-unsettled keep-parked siblings"
                    );
                }
                let row_removed = self.schedule.mark_completed(&job_id);
                // A recursive `Swarm` subagent finished (GOALS §24): free
                // its concurrency slot and start the next queued spawn, before
                // anything else, so the global cap accounting stays tight even
                // if the injected turn below is long-running. Done here on the
                // main thread — the authority is the single scheduler.
                if matches!(kind, crate::engine::schedule::ScheduleKind::Swarm) {
                    // Free the slot only when THIS drain removed the live row.
                    // A swarm job can have two terminal producers (its runner
                    // and a racing `cancel()`, which frees the slot itself), so
                    // gating on the one-time row removal keeps the running-swarm
                    // count decremented exactly once (#108). A duplicate
                    // `Completed` for an already-reconciled job finds no row and
                    // must not free the slot a second time.
                    if row_removed {
                        self.schedule.swarm_completed();
                    }
                    // Fire the paired `subagentStop` for a genuine swarm child.
                    // No-op for a goal-supervision worker (never in the map;
                    // guidance L22) — its dedicated completion handling runs
                    // below. Idempotent via the tracking map, so a rare
                    // duplicate `Completed` fires it at most once per child.
                    self.fire_swarm_subagent_stop_if_tracked(&job_id, failed)
                        .await;
                }
                if self
                    .handle_goal_supervision_completion(&job_id, &result, failed, input_rx, tx)
                    .await?
                {
                    return Ok(());
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
                if let Err(e) = self
                    .session
                    .db
                    .raise_interrupt(self.session.id, "schedule", &note, None)
                    .await
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
                    scheduled_job_submission(injected, Some(job_id.clone())),
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
                let child = match self.resolve_child_cwd(parsed.cwd.as_deref(), None) {
                    Ok(child) => child,
                    Err(message) => return Ok(message),
                };
                // Resolve the launch environment before accepting the
                // approval. This is pure local validation; keeping a refused
                // sandbox configuration outside the handoff scope means an
                // approved operation always reaches the real spawn boundary
                // (or is recorded submission-unknown if that boundary fails
                // unexpectedly).
                let launch = match self.resolve_background_launch(&child.resolved).await {
                    Ok(launch) => launch,
                    Err(refusal) => return Ok(refusal),
                };
                // `schedule` actions execute on the driver authority rather
                // than through the ordinary tool dispatcher. Keep this direct
                // shell-launch boundary in the same typed approval scope as
                // normal tools so an approved command cannot be consumed by
                // the helper and then escape without a terminal handoff
                // receipt.
                let cancel = self
                    .cancel_current
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                    .unwrap_or_else(tokio_util::sync::CancellationToken::new);
                let effect_cancel = cancel.clone();
                crate::engine::interrupt::with_host_approval_effect_scope(
                    "schedule_background_start",
                    cancel,
                    async {
                        if let Some(refusal) = self.approve_background_command(&parsed.command).await? {
                            return Ok(refusal);
                        }
                        crate::engine::interrupt::recheck_host_approval_effect_boundary(
                            "schedule_background_start",
                            &effect_cancel,
                            &[serde_json::json!({"execute": {"command": &parsed.command}})],
                        )
                        .await?;
                        let job_id = self
                            .schedule
                            .start_background(parsed, child.resolved, launch);
                        Ok(format!(
                            "started background `{job_id}` — tail with schedule(action=\"background.tail\", args={{\"job_id\":\"{job_id}\"}})"
                        ))
                    },
                    // `start_background` has synchronously handed the command
                    // to the background runner before returning its job id.
                    // The only earlier successful return is a denied approval,
                    // which has no registered handoff.
                    |_| Some(true),
                )
                .await
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

    async fn approve_background_command(&self, command: &str) -> Result<Option<String>> {
        let Some(approver) = self.approver.as_ref() else {
            return Ok(Some(
                "Error: background command requires approval, but no approver is available"
                    .to_string(),
            ));
        };
        match approver
            .authorize(crate::approval::AuthorizationRequest::Command { command })
            .await?
        {
            crate::approval::Decision::Allow { .. } => Ok(None),
            crate::approval::Decision::NoninteractiveDeny => {
                Ok(Some(crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string()))
            }
            crate::approval::Decision::StandingReject { scope } => Ok(Some(
                crate::approval::standing_reject_refusal("schedule", scope),
            )),
            crate::approval::Decision::Deny => Ok(Some(
                "Error: background command approval denied; no background job was started"
                    .to_string(),
            )),
        }
    }

    async fn resolve_background_launch(
        &self,
        cwd: &std::path::Path,
    ) -> std::result::Result<crate::engine::schedule::background::BackgroundLaunch, String> {
        let agent = &self
            .stack
            .last()
            .expect("driver stack is never empty")
            .agent;
        let session_env = agent
            .env_overlay
            .read()
            .map(|env| env.clone())
            .unwrap_or_default();
        // `schedule` is intercepted before normal tool dispatch and can start
        // a shell directly. Recreate the KB trust fence at this authority
        // boundary: protected roots force zerobox confinement even when the
        // ordinary session sandbox is disabled.
        let denied_knowledge_paths = crate::knowledge::denied_local_knowledge_roots_for_model(
            &self.cwd,
            &self.config.extended(),
            agent.model.is_trusted(),
        )
        .map_err(|error| {
            format!("Error: cannot resolve local knowledge-base access policy: {error}")
        })?;
        let sandbox_on = self.session.sandbox_enabled() || !denied_knowledge_paths.is_empty();
        let availability = if sandbox_on {
            background_sandbox_availability(cwd).await
        } else {
            crate::tools::shell_sandbox::SandboxAvailability::Available
        };
        match crate::engine::schedule::background::background_launch_gate(sandbox_on, &availability)
        {
            crate::tools::shell_sandbox::SandboxGate::Unconfined => {
                Ok(crate::engine::schedule::background::BackgroundLaunch::unconfined(session_env))
            }
            crate::tools::shell_sandbox::SandboxGate::Confine => Ok(
                crate::engine::schedule::background::BackgroundLaunch::confined_with_denied_knowledge_paths(
                    self.session.tmp_dir(),
                    session_env,
                    denied_knowledge_paths,
                ),
            ),
            crate::tools::shell_sandbox::SandboxGate::Refuse { reason } => {
                if denied_knowledge_paths.is_empty() {
                    Err(background_sandbox_unavailable_refusal(&reason))
                } else {
                    Err(background_knowledge_sandbox_unavailable_refusal(&reason))
                }
            }
        }
    }

    pub(in crate::engine::driver) async fn record_schedule_tool_call(
        &self,
        row: ScheduleToolCallRecord,
    ) {
        // A `schedule` action is dispatched to the main-thread authority, not
        // through the ordinary tool-dispatch path, so — unlike every other tool
        // — it never wrote a `tool_call` row to the export timeline; the export
        // (which reads `session_events`) showed only failed bash/mcp detours,
        // never the successful native call (implementation note,
        // §5). Mirror the ordinary-tool pattern: persist BOTH the
        // `tool_call_events` row (`/stats`, history) AND a `tool_call`
        // `session_events` row (the export's dispatch record).
        let (recovery_kind, recovery_stage) = row.recovery.db_fields();
        // The `schedule` tool_call payload carries MODEL-AUTHORED free text —
        // `original_input`/`wire_input` are the scheduling model's own tool
        // arguments (and `output` can echo them back), so a session-table literal
        // the model placed in a schedule arg would otherwise persist raw with no
        // history row. Route it through the frame-carrying journaling path exactly
        // like every ordinary tool_call (engine/agent/tool_dispatch.rs) does, using
        // the authoring (foreground) agent's model identity + pre-policy session
        // table: a trusted author journals its matched literals (or fail-closed
        // scrubs), an untrusted author journals nothing (payload already
        // post-redaction). The foreground stack top is the agent that emitted this
        // `schedule` call — the same agent captured in `row.agent` — because a
        // schedule action dispatches background work without popping the caller's
        // frame.
        let active_model = &self
            .stack
            .last()
            .expect("driver stack is never empty")
            .agent
            .model;
        let providers = self.config.providers();
        // A Responses `schedule` call is intercepted before ordinary dispatch,
        // so retain its dual provider identity here rather than manufacturing
        // an identity from the Rig correlation handle. Other wires have no
        // item handle; their correlation handle is the only item fallback.
        let provider_item_id = row
            .provider_item_id
            .clone()
            .unwrap_or_else(|| row.call_id.clone());
        let provider_identity = crate::session::ToolCallProviderIdentity::from_provider_call(
            Some(active_model.provider_id()),
            Some(active_model.model_id_ref()),
            Some(&providers),
            Some(active_model.current_wire_api()),
            provider_item_id,
            row.provider_call_id.clone(),
        );
        let schedule_session_table = active_model.session_redact_table();
        // ONE authoring frame drives BOTH the timeline event and the co-persisted
        // audit row, so their journal-vs-scrub decisions come from a single
        // source: the AUTHORING (stack-top) model's `(provider, model)` + config +
        // pre-policy table — never the session's after-turn primary. Trust is read
        // via `frame.resolved_trusted()` (config-snapshot `resolve_trust`), the
        // exact expression the session event resolves internally, so an
        // untrusted-primary→trusted-failover author is classified by the author
        // and the audit row stays consistent with its event (finding r11-3).
        let schedule_frame = crate::session::SessionEventModelFrame {
            provider_id: active_model.provider_id(),
            model_id: active_model.model_id_ref(),
            config: &self.config,
            session_table: schedule_session_table.as_ref(),
        };
        let schedule_target_trusted = schedule_frame.resolved_trusted();
        let schedule_event_data = serde_json::json!({
            "tool": "schedule",
            "original_input": row.original_input_json,
            "wire_input": row.wire_input_json,
            "recovery_kind": recovery_kind,
            "recovery_stage": recovery_stage,
            "hard_fail": row.hard_fail,
            "output": row.output,
            "truncated": false,
            "duration_ms": row.duration_ms,
        });
        if let Err(e) = self
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some(&row.agent),
                Some(&row.call_id),
                schedule_frame,
                &schedule_event_data,
            )
            .await
        {
            tracing::warn!(error = %e, "recording schedule timeline event failed");
        }
        if let Err(e) = self
            .session
            .record_tool_call_journaled(
                crate::session::ToolCallRow {
                    event_id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    agent: row.agent,
                    call_id: row.call_id,
                    parent_call_id: None,
                    parent_child_index: None,
                    identity: provider_identity,
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
                    // The schedule meta-tool's fixed minimal-schema repair fingerprint is not
                    // threaded through `ScheduleToolCallRecord`; the §12 fingerprint telemetry
                    // covers the per-tool dispatch path.
                    shape_fingerprint: None,
                    // The hint layer is `bash`-only; a `schedule` call never carries one.
                    hint: None,
                },
                schedule_frame.session_table,
                schedule_target_trusted,
            )
            .await
        {
            tracing::warn!(error = %e, "persisting schedule tool_call_event failed");
        }
    }
}

fn background_sandbox_unavailable_refusal(reason: &str) -> String {
    format!(
        "Error: the shell sandbox cannot start here ({reason}); `background.start` will fail until the user types `/sandbox off` in the cockpit composer (a UI command, not a shell command) — ask them to do that; do not retry or run `/sandbox off` yourself."
    )
}

fn background_knowledge_sandbox_unavailable_refusal(reason: &str) -> String {
    format!(
        "Access denied: `background.start` is unavailable for this model because a local knowledge base requires a trusted model and the shell sandbox cannot start here ({reason}). A background command must remain confined so it cannot read or write that knowledge base."
    )
}

#[cfg(not(test))]
async fn background_sandbox_availability(
    cwd: &std::path::Path,
) -> crate::tools::shell_sandbox::SandboxAvailability {
    crate::tools::shell_sandbox::sandbox_available(cwd)
        .await
        .clone()
}

#[cfg(test)]
tokio::task_local! {
    static TEST_BACKGROUND_SANDBOX_AVAILABILITY:
        std::cell::RefCell<Option<crate::tools::shell_sandbox::SandboxAvailability>>;
}

#[cfg(test)]
async fn background_sandbox_availability(
    cwd: &std::path::Path,
) -> crate::tools::shell_sandbox::SandboxAvailability {
    if let Some(availability) = TEST_BACKGROUND_SANDBOX_AVAILABILITY
        .try_with(|slot| slot.borrow().clone())
        .ok()
        .flatten()
    {
        return availability;
    }
    crate::tools::shell_sandbox::sandbox_available(cwd)
        .await
        .clone()
}

#[cfg(test)]
pub(in crate::engine::driver) async fn with_background_sandbox_availability_for_test<F>(
    availability: crate::tools::shell_sandbox::SandboxAvailability,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    TEST_BACKGROUND_SANDBOX_AVAILABILITY
        .scope(std::cell::RefCell::new(Some(availability)), future)
        .await
}
