use std::ops::ControlFlow;

use super::*;

pub(crate) struct TurnCtx<'a> {
    pub(crate) agent: &'a Agent,
    pub(crate) model: &'a Model,
    pub(crate) session: &'a Arc<Session>,
    pub(crate) locks: &'a Arc<crate::locks::LockManager>,
    pub(crate) redact: &'a Arc<RedactionTable>,
    pub(crate) cwd: &'a std::path::Path,
    pub(crate) interrupts: &'a Arc<crate::engine::interrupt::InterruptHub>,
    pub(crate) cancel: &'a tokio_util::sync::CancellationToken,
    pub(crate) approver: Option<&'a Arc<crate::approval::Approver>>,
    pub(crate) lsp: Option<&'a Arc<crate::daemon::lsp::LspManager>>,
    pub(crate) resource_scheduler:
        Option<&'a Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    pub(crate) loop_guard_threshold: u32,
    pub(crate) is_root: bool,
    pub(crate) deferred_log: crate::engine::deferred::DeferredLog,
    pub(crate) seeds: crate::engine::seed_collector::SeedCollector,
    pub(crate) emit_inference_error_ui: bool,
    pub(crate) call_id: Uuid,
    pub(crate) tandem: Option<&'a crate::engine::schedule::TandemSet>,
    pub(crate) turn_id: Option<String>,
    pub(crate) tx: &'a mpsc::Sender<TurnEvent>,
}

pub(crate) fn phase_01_pre_send_history_mutation() {}
pub(crate) fn phase_02_dispatch_time_record() {}
pub(crate) fn phase_03_tandem_shadow_dispatch() {}
pub(crate) fn phase_04_inference_call() {}
pub(crate) fn phase_05_settle_completed_record() {}
pub(crate) fn phase_06_post_inference_text_processing() {}
pub(crate) fn phase_07_history_push() {}
pub(crate) fn phase_08_text_embedded_tool_call_recovery() {}
pub(crate) fn phase_09_terminal_text_emit() {}

pub(crate) async fn phase_10_dispatch_one_call(
    agent: &Agent,
    session: &Arc<Session>,
    cwd: &std::path::Path,
    tx: &mpsc::Sender<TurnEvent>,
    tc: &ToolCall,
    resolved_name: &str,
) -> Result<ControlFlow<TurnOutcome, ()>> {
    macro_rules! return_structural {
        ($outcome:expr) => {
            return Ok(ControlFlow::Break($outcome));
        };
    }
    // `task` is special — it's a structural tool the driver
    // handles. For interactive subagents (builder) the driver
    // performs a primary handoff via [`TurnOutcome::SpawnSubagent`];
    // for noninteractive ones (explore) it runs the child inline
    // and returns the result as this task call's tool_result via
    // [`TurnOutcome::SpawnNoninteractive`]. Other tool calls in
    // the same assistant turn are dropped — the model will re-
    // emit them on the next turn once it has the task result.
    if resolved_name == "task" {
        let known_task_call_ids = match session.db.list_task_delegation_children(session.id) {
            Ok(rows) => rows
                .into_iter()
                .map(|row| row.task_call_id)
                .collect::<std::collections::BTreeSet<_>>(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tool = "task",
                    "load task delegation ids for fresh/control repair failed"
                );
                std::collections::BTreeSet::new()
            }
        };
        let parsed = match crate::tools::task_repair::parse_task_args(
            &tc.function.arguments,
            &known_task_call_ids,
        ) {
            Ok(parsed) => parsed,
            Err(err) => {
                if let Err(e) = session.record_tool_rejected(
                    &agent.name,
                    &tc.id,
                    "task",
                    "task_intent_parse_failed",
                ) {
                    tracing::warn!(error = %e, tool = "task", "record tool_rejected event failed");
                }
                return_structural!(task_refusal(
                    &tc.id,
                    tc.call_id.clone(),
                    err.model_message(),
                ));
            }
        };
        if !parsed.notes().is_empty() {
            tracing::info!(
                tool = "task",
                repair_kind = "task_intent_canonicalized",
                notes = ?parsed.notes(),
                "task arguments canonicalized"
            );
        }
        match parsed {
            crate::tools::task_repair::ParsedTaskArgs::Control {
                intent, control, ..
            } => {
                let action = match intent {
                    crate::tools::task_repair::TaskControlIntent::Models => {
                        TaskControlAction::Models
                    }
                    crate::tools::task_repair::TaskControlIntent::List => TaskControlAction::List,
                    crate::tools::task_repair::TaskControlIntent::Status => {
                        TaskControlAction::Status
                    }
                    crate::tools::task_repair::TaskControlIntent::Cancel => {
                        TaskControlAction::Cancel
                    }
                    crate::tools::task_repair::TaskControlIntent::Query => TaskControlAction::Query,
                    crate::tools::task_repair::TaskControlIntent::Steer => TaskControlAction::Steer,
                };
                let target_task_call_id = control
                    .get("task_call_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let label = control
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let message = control
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                return_structural!(TurnOutcome::TaskControl {
                    action,
                    target_task_call_id,
                    label,
                    message,
                    task_call_id: tc.id.clone(),
                    task_function_call_id: tc.call_id.clone(),
                });
            }
            crate::tools::task_repair::ParsedTaskArgs::Batch {
                entries: items,
                why,
                notes: repair_notes,
            } => {
                let max_parallel = crate::config::extended::load_for_cwd(cwd)
                    .delegation
                    .max_parallel
                    .max(1);
                if items.is_empty() || items.len() > max_parallel {
                    return_structural!(task_refusal(
                        &tc.id,
                        tc.call_id.clone(),
                        format!("`batch` must contain 1 to {max_parallel} entries"),
                    ));
                }
                let mut labels = std::collections::HashSet::new();
                let mut entries = Vec::new();
                for item in &items {
                    if item.get("mode").is_some() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            "`mode` is not supported inside `batch[]`",
                        ));
                    }
                    let child = item
                        .get("agent")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("");
                    let prompt = item
                        .get("prompt")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("");
                    if child.is_empty() || prompt.is_empty() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            "`batch[]` entries require `agent` and non-empty `prompt`",
                        ));
                    }
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            if items.len() == 1 {
                                child.to_string()
                            } else {
                                String::new()
                            }
                        });
                    if label.is_empty() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            "`label` is required when `batch` contains more than one entry",
                        ));
                    }
                    if !labels.insert(label.clone()) {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            format!("duplicate batch label `{label}`"),
                        ));
                    }
                    if !crate::engine::builtin::is_noninteractive(child) {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            format!("batch entry `{label}` targets interactive agent `{child}`"),
                        ));
                    }
                    let model =
                        match crate::engine::model_roles::DelegationModelSelector::from_value(
                            item.get("model"),
                        ) {
                            Ok(model) => model,
                            Err(err) => {
                                return_structural!(task_refusal(
                                    &tc.id,
                                    tc.call_id.clone(),
                                    format!(
                                        "batch entry `{label}` has invalid model selector: {err}"
                                    ),
                                ));
                            }
                        };
                    let resume_handle = item
                        .get("resume_handle")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    let remaining_depth = match task_remaining_depth(item) {
                        Ok(depth) => depth,
                        Err(err) => {
                            return_structural!(task_refusal(
                                &tc.id,
                                tc.call_id.clone(),
                                format!("batch entry `{label}` has invalid depth: {err}"),
                            ));
                        }
                    };
                    let cwd = item
                        .get("cwd")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    let output_dir = item
                        .get("output_dir")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    entries.push(BatchTaskEntry {
                        label,
                        child_agent: child.to_string(),
                        prompt: prompt.to_string(),
                        model,
                        remaining_depth,
                        resume_handle,
                        cwd,
                        granted_tools: task_string_array(item, "grant_tools"),
                        seeds: task_seed_array(item),
                        todo_ids: task_todo_ids(item),
                        skill_seed: task_string_array(item, "skill_seed"),
                        output_dir,
                    });
                }
                return_structural!(TurnOutcome::SpawnNoninteractiveBatch {
                    entries,
                    why,
                    repair_notes,
                    task_call_id: tc.id.clone(),
                    task_function_call_id: tc.call_id.clone(),
                });
            }
            crate::tools::task_repair::ParsedTaskArgs::Delegate {
                args,
                notes: repair_notes,
            } => {
                let prompt = args
                    .get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let child = args
                    .get("agent")
                    .and_then(Value::as_str)
                    .unwrap_or("builder")
                    .to_string();
                // Re-queryable-subagent fields (GOALS §3c). Both are present in the
                // `task` schema from session start (cache-safe fixed shape); the
                // capability is gated behaviorally in the driver, not here.
                let why = args
                    .get("why")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let resume_handle = args
                    .get("resume_handle")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let cwd = args
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let mode = args.get("mode").and_then(Value::as_str);
                let model = match crate::engine::model_roles::DelegationModelSelector::from_value(
                    args.get("model"),
                ) {
                    Ok(model) => model,
                    Err(err) => {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.call_id.clone(),
                            format!("invalid model selector: {err}"),
                        ));
                    }
                };
                let noninteractive = resolve_interactivity(mode, &child, resume_handle.is_some());
                let remaining_depth = match task_remaining_depth(&args) {
                    Ok(depth) => depth,
                    Err(err) => {
                        return_structural!(task_refusal(&tc.id, tc.call_id.clone(), err));
                    }
                };
                // Per-delegation tool grants (`task.grant_tools`, prompt
                // `parent-granted-tools.md`): the parent may attach extra tools to
                // this one delegation. Present in the `task` schema from session
                // start (cache-safe fixed shape); the driver validates each grant
                // against the target's role invariants before building the child.
                // Collected loosely here (trimmed, de-blanked, de-duplicated);
                // role-invariant rejection happens at the single driver chokepoint.
                let granted_tools = task_string_array(&args, "grant_tools");
                // Caller→child read-only pre-seeds (`task.seed`,
                // implementation note): the parent may attach
                // read-only tool calls to pre-load the child's context. Present in
                // the `task` schema from session start (cache-safe fixed shape).
                // Collected loosely here — keep only well-formed `{tool, args}`
                // entries naming a read-only tool with object args (the SAME
                // read-only rule the `seed` tool enforces, `is_read_only_seed_tool`);
                // a write/lock/bash entry is dropped, never executed. The driver
                // re-executes each survivor in the CHILD's cwd; a per-entry
                // execution failure there is surfaced as a failed seed, not an abort.
                let seeds = task_seed_array(&args);
                // Parent→child skill seeds (`task.skill_seed`,
                // implementation note): names of active skills
                // the parent wants seeded (instructions + framing) into the child.
                // Collected loosely here (trimmed, de-blanked, de-duplicated); the
                // single driver chokepoint validates each against the parent's
                // active-skill set and deterministically strips a non-active name
                // with a model-visible note. Carries skill INSTRUCTIONS, not a
                // re-executed tool call (that is `seed`) — kept fully separate.
                let skill_seed = task_string_array(&args, "skill_seed");
                let todo_ids = task_todo_ids(&args);
                if !noninteractive {
                    // Timeline event (Part B): an interactive `task`
                    // delegation spawned a child. Noninteractive children
                    // are recorded by the driver after cwd validation.
                    let task_identity =
                        crate::engine::task_identity::TaskProviderIdentity::for_task_call(
                            &tc.id,
                            tc.call_id.as_deref(),
                        );
                    let routing = agent.model.routing_metadata_json(None);
                    if let Err(e) = session.record_event(
                        crate::db::session_log::SessionEventKind::SubagentSpawned,
                        Some(&agent.name),
                        Some(&tc.id),
                        &serde_json::json!({
                            "child_agent": child,
                            "task_call_id": tc.id,
                            "provider_call_id": task_identity.provider_call_id,
                            "provider_call_id_source": task_identity.provider_call_id_source,
                            "provider_identity": task_identity.event_identity_json(&tc.id),
                            "label": "default",
                            "noninteractive": false,
                            "prompt": prompt,
                            "mode": mode,
                            "model": model.as_ref().map(|selector| selector.to_json()),
                            "trusted_only": agent.model.trusted_only_enabled(),
                            "model_trusted": agent.model.is_trusted(),
                            "routing": routing.clone(),
                            "remaining_depth": remaining_depth,
                            "why": why,
                            "resume_handle": resume_handle.clone(),
                            "grant_tools": granted_tools.clone(),
                            "seed": seeds.clone(),
                            "skill_seed": skill_seed.clone(),
                            "todo_ids": todo_ids.clone(),
                        }),
                    ) {
                        tracing::warn!(error = %e, "record subagent_spawned event failed");
                    }
                    let _ = tx
                        .send(TurnEvent::SubagentSpawned {
                            parent: agent.name.clone(),
                            child: child.clone(),
                            task_call_id: tc.id.clone(),
                            label: "default".to_string(),
                            prompt: prompt.clone(),
                            requested_cwd: None,
                            resolved_cwd: None,
                            trusted_only: agent.model.trusted_only_enabled(),
                            model_trusted: agent.model.is_trusted(),
                            routing,
                        })
                        .await;
                    return_structural!(TurnOutcome::SpawnSubagent {
                        child_agent: child,
                        prompt,
                        model,
                        remaining_depth,
                        granted_tools,
                        seeds,
                        todo_ids,
                        skill_seed,
                        repair_notes,
                        task_call_id: tc.id.clone(),
                        task_function_call_id: tc.call_id.clone(),
                    });
                }
                return_structural!(TurnOutcome::SpawnNoninteractive {
                    child_agent: child,
                    prompt,
                    model,
                    remaining_depth,
                    why,
                    resume_handle,
                    cwd,
                    granted_tools,
                    seeds,
                    todo_ids,
                    skill_seed,
                    repair_notes,
                    task_call_id: tc.id.clone(),
                    task_function_call_id: tc.call_id.clone(),
                });
            }
        }
    }

    // `schedule` is structural in the **main** conversation: the driver
    // owns the single async-job authority (GOALS §22), so the action
    // is routed there via [`TurnOutcome::ScheduleAction`]. Inside an
    // ephemeral-fork loop iteration the toolbox instead carries the
    // in-process `ForkScheduleTool` (alongside `note`) — there, `schedule`
    // is dispatched normally and re-routes create-actions to requests
    // (forks cannot spawn scheduled work). We tell the two apart by the
    // fork-only `note` tool: present only inside a loop fork.
    if resolved_name == "schedule" && agent.tools.get("note").is_none() {
        let original_args = tc.function.arguments.clone();
        let mut args = tc.function.arguments.clone();
        // Validate + repair the loose outer object against the `schedule`
        // tool's own minimal `{action, args}` schema; per-action
        // validation runs in the driver through the same repair
        // contract (§12). The outer schema is permissive (`args` is a
        // free-form object), so this only catches a malformed `action`.
        let schedule_schema = agent
            .tools
            .get("schedule")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let recovery = repair(&mut args, &schedule_schema, "schedule").recovery;
        return_structural!(TurnOutcome::ScheduleAction {
            original_args,
            args,
            recovery,
            task_call_id: tc.id.clone(),
            task_function_call_id: tc.call_id.clone(),
        });
    }

    // `handoff` is structural: the driver owns the single primary-swap
    // authority (same idle-boundary mechanism as `/plan`/`/build`), so
    // the `Auto` front door routes the chosen target there via
    // [`TurnOutcome::Handoff`] rather than dispatching a tool here.
    if resolved_name == "handoff" {
        let schema = agent
            .tools
            .get("handoff")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let target = handoff_target(&tc.function.arguments, &schema);
        return_structural!(TurnOutcome::Handoff {
            target,
            task_call_id: tc.id.clone(),
            task_function_call_id: tc.call_id.clone(),
        });
    }

    // `spawn` is structural: the driver routes the spawn to the
    // single async-job authority (GOALS §22/§24), which enforces the depth
    // ceiling + global concurrency cap and schedules the child `Swarm`
    // subagent as a parallel background job. Only `Swarm` holds it.
    if resolved_name == "spawn" {
        let schema = agent
            .tools
            .get("spawn")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let mut args = tc.function.arguments.clone();
        let _ = repair(&mut args, &schema, "spawn");
        let prompt = args
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let output_dir = args
            .get("output_dir")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let model = args
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return_structural!(TurnOutcome::Spawn {
            prompt,
            output_dir,
            model,
            task_call_id: tc.id.clone(),
            task_function_call_id: tc.call_id.clone(),
        });
    }

    // `return` is structural: a delegated subagent finishes by reporting a
    // structured summary to its caller. The driver assembles the envelope
    // (model fields + host-derived `files_changed`) and injects it as the
    // delegation's tool result. Validate-then-repair the fields against the
    // tool's own schema (§12) so a weak model's loose object still yields a
    // well-formed envelope; an unparseable field defaults to empty in
    // [`crate::engine::envelope::Envelope::from_return_args`].
    if resolved_name == "return" {
        let schema = agent
            .tools
            .get("return")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let mut fields = tc.function.arguments.clone();
        let _ = repair(&mut fields, &schema, "return");
        return_structural!(TurnOutcome::Return { fields });
    }

    Ok(ControlFlow::Continue(()))
}

pub(crate) async fn run_turn(
    ctx: TurnCtx<'_>,
    history: &mut Vec<Message>,
    prompt: Message,
) -> Result<TurnOutcome> {
    let agent = ctx.agent;
    let model = ctx.model;
    let session = Arc::clone(ctx.session);
    let locks = Arc::clone(ctx.locks);
    let redact = Arc::clone(ctx.redact);
    let cwd = ctx.cwd.to_path_buf();
    let interrupts = Arc::clone(ctx.interrupts);
    let cancel = ctx.cancel.clone();
    let approver = ctx.approver.cloned();
    let lsp = ctx.lsp.cloned();
    let resource_scheduler = ctx.resource_scheduler.cloned();
    let loop_guard_threshold = ctx.loop_guard_threshold;
    let is_root = ctx.is_root;
    let deferred_log = ctx.deferred_log;
    let seeds = ctx.seeds;
    let emit_inference_error_ui = ctx.emit_inference_error_ui;
    let call_id = ctx.call_id;
    let tandem = ctx.tandem;
    let turn_id = ctx.turn_id;
    let tx = ctx.tx;

    phase_01_pre_send_history_mutation();
    phase_02_dispatch_time_record();
    phase_03_tandem_shadow_dispatch();
    phase_04_inference_call();
    phase_05_settle_completed_record();
    phase_06_post_inference_text_processing();
    phase_07_history_push();
    phase_08_text_embedded_tool_call_recovery();
    phase_09_terminal_text_emit();

    let active_tools = turn_toolbox(agent, &session);
    let tools = active_tools.definitions(agent.llm_mode);

    if let Some(notice) = session.sandbox_escalation_turn_notice() {
        history.push(Message::System { content: notice });
    }

    // Tell the TUI we've called the model — `Thinking…` shows until the
    // first AssistantTextDelta arrives.
    let _ = tx
        .send(TurnEvent::ThinkingStarted {
            agent: agent.name.clone(),
            turn_id,
        })
        .await;

    // Stamp the send time for the cache-cold predicate's TTL arm
    // (GOALS §10). Done right before the round-trip so "time since last
    // send" measures from when the provider last saw (and cached) the
    // prefix.
    session.note_send();

    inject_initial_project_guidance(&agent.name, history, &cwd, redact.clone(), tx).await;

    // Live instructions-file diff injection (prompt
    // `instructions-file-live-diff.md`). Guidance now rides as user-role
    // project notes rather than raw system text, so live in-place edits do the
    // same. Gated to the session root: subagents inject their own current
    // guidance once when their first model turn starts. The baseline advances
    // on inject, so each distinct change is injected exactly once.
    if is_root && let Some(message) = session.guidance_change_injection(&cwd) {
        inject_live_project_guidance_change(history, &cwd, redact.clone(), tx, &message).await;
    }

    // Live pre-send pairing heal (implementation note).
    // The history sent to the provider must never carry an orphan `tool_use`
    // (a tool call with no matching `tool_result`) — strict providers 400 on
    // it. A structural tool (`task`/`handoff`/`spawn`/`done`/`schedule`/`return`)
    // returns early from the dispatch loop, so any sibling `tool_use` in the
    // same assistant turn never gets a result and lingers as an orphan in
    // `history`. We heal it here, immediately before the request is assembled,
    // using the SAME helper the resume path uses (single source of truth).
    // `prompt` is the not-yet-pushed message that follows `history` on the
    // wire (the user message, or — after a structural tool — that tool's own
    // driver-injected `tool_result`), so naming its result ids keeps the
    // structural tool's pending result from being double-stubbed. A no-op
    // (no allocation, no heal) on the already-paired common path. A heal is a
    // rare backstop (the dispatch loop normally pairs every call), so it is
    // surfaced via a warn log rather than a durable row — the stubbed result is
    // a synthetic wire-only artifact, never part of the persisted transcript
    // (which records each real call's own result), so it must not enter the
    // session log lest it pollute rehydration's pairing rebuild.
    for heal in crate::engine::rehydrate::heal_live_history(history, &prompt) {
        if let crate::engine::repair::Recovery::ResumeHeal { kind, id } = heal {
            tracing::warn!(
                agent = %agent.name,
                kind = %kind,
                call_id = %id,
                "live pre-send heal stubbed/dropped an orphan tool pairing"
            );
        }
    }

    let endpoint_recovery =
        interrupts
            .is_interactive_attached()
            .then(|| crate::engine::model::EndpointRecoveryContext {
                approve: {
                    let session = session.clone();
                    let interrupts = interrupts.clone();
                    let agent_name = agent.name.clone();
                    std::sync::Arc::new(move |prompt| {
                        let session = session.clone();
                        let interrupts = interrupts.clone();
                        let agent_name = agent_name.clone();
                        Box::pin(async move {
                            const ID_TRY: &str = "try_alternate";
                            const ID_CANCEL: &str = "cancel";
                            let label = |wire_api| match wire_api {
                                crate::config::providers::WireApi::Completions => {
                                    "Chat Completions"
                                }
                                crate::config::providers::WireApi::Responses => "Responses",
                                crate::config::providers::WireApi::Auto => "auto",
                            };
                            let set = crate::daemon::proto::InterruptQuestionSet {
                                questions: vec![crate::daemon::proto::InterruptQuestion::Single {
                                    prompt: format!(
                                        "`{}/{}` failed on the {} endpoint. Try {} instead?",
                                        prompt.provider,
                                        prompt.model,
                                        label(prompt.attempted),
                                        label(prompt.alternate)
                                    ),
                                    options: vec![
                                        crate::daemon::proto::InterruptOption {
                                            id: ID_TRY.to_string(),
                                            label: format!("Try {}", label(prompt.alternate)),
                                            description: Some(
                                                "Retries this turn on the alternate endpoint and saves it if successful."
                                                    .to_string(),
                                            ),
                                        },
                                        crate::daemon::proto::InterruptOption {
                                            id: ID_CANCEL.to_string(),
                                            label: "Cancel".to_string(),
                                            description: Some(
                                                "Surface the endpoint mismatch without retrying."
                                                    .to_string(),
                                            ),
                                        },
                                    ],
                                    allow_freetext: false,
                                    command_detail: None,
                                    permission: false,
                                    sandbox_escalation: None,
                                }],
                            };
                            let response = crate::engine::interrupt::raise_and_wait(
                                &session.db,
                                &interrupts,
                                session.id,
                                &agent_name,
                                "OpenAI-compatible endpoint recovery",
                                set,
                                "endpoint recovery",
                            )
                            .await;
                            crate::engine::interrupt::selected_id_of(&response).as_deref()
                                == Some(ID_TRY)
                        })
                            as futures::future::BoxFuture<'static, bool>
                    })
                },
            });

    // Dispatch-time recording (`inference-timeout-and-failure-
    // observability.md` #4): persist the attempt's captured body BEFORE the
    // call returns, with status `pending`, so a hung or failed turn still
    // exports an inference record instead of an empty export. The same
    // `call_id` keys the terminal update below. The timeline EVENT is recorded
    // once on settle (the `inference_request` event on success, the
    // `inference_failure` event on failure) — both carry this `call_id`, so the
    // export's file-per-call pass picks up the record either way without
    // double-counting. Best-effort: auditing must never break a live turn (same
    // posture as the existing post-success write).
    let prepared_request = model.prepare_completion_request(
        &agent.system,
        history,
        &prompt,
        &tools,
        &agent.params,
        endpoint_recovery.is_some(),
    )?;
    let dispatch_payload = with_phases(
        prepared_request.captured.clone(),
        &serde_json::json!({ "dispatched_ms": 0 }),
    );
    let pending_record = {
        let session = session.clone();
        let payload = dispatch_payload.clone();
        let handle = tokio::spawn(async move {
            record_inference_request_async(
                session,
                call_id,
                payload,
                crate::db::session_log::InferenceRequestStatus::Pending,
            )
            .await
            .map_err(|e| e.to_string())
        });
        async move {
            handle
                .await
                .map_err(|e| format!("record_inference_request task join failed: {e}"))?
        }
        .boxed()
        .shared()
    };

    // Model-comparison tandem (shadow) dispatch (`model-comparison-
    // tandem-inference.md`). Fired HERE — right before the main call, after the
    // exact post-redaction history is assembled (incl. any live guidance-diff
    // injection above) — so each tandem model receives a byte-identical body to
    // the main model's, on the SAME `call_id`. A pure DB-only observer: never
    // executed, never enters history, never affects this turn's control flow.
    // `None` on the backup attempt so a fallback retry doesn't double-shadow.
    // Skipped for utility calls automatically — those never run through `turn`.
    if let Some(set) = tandem.filter(|s| s.is_enabled()) {
        let dispatch = crate::engine::schedule::TandemDispatch {
            parent_call_id: call_id.to_string(),
            agent: agent.name.clone(),
            system: agent.system.clone(),
            history: history.clone(),
            prompt: prompt.clone(),
            tools: tools.clone(),
            params: agent.params.clone(),
        };
        crate::engine::schedule::tandem::dispatch_turn(&session, set, dispatch);
    }

    let completion = model
        .complete_prepared_with_pre_drain(
            prepared_request,
            &tools,
            agent.params.clone(),
            &agent.name,
            Some(tx),
            &cancel,
            endpoint_recovery,
            Some(pending_record.clone()),
        )
        .await;

    let ((msg_id, choice, usage), captured_request, timing) = match completion {
        Ok(out) => out,
        Err(e) => {
            if let Err(record_err) = pending_record.clone().await {
                return Err(anyhow::anyhow!(
                    "record_inference_request (dispatch) failed: {record_err}"
                ));
            }
            // Settle the dispatch-time record to its terminal status and
            // surface the failure (inline error + recorded event), unless this
            // was a clean cancel / drain unwind (those keep their dedicated
            // sentinels and are handled by the driver without a red error).
            record_inference_outcome(
                InferenceOutcomeRecord {
                    session: session.clone(),
                    call_id,
                    dispatch_payload: &dispatch_payload,
                    agent_name: &agent.name,
                    wire_api: model.wire_api_label(),
                    routing_metadata: model.routing_metadata_json(None),
                    emit_inference_error_ui,
                    tx,
                },
                &e,
            )
            .await;
            return Err(e.context(format!("completion call for agent `{}`", agent.name)));
        }
    };

    // Settle the dispatch-time record to `completed`, folding in the phase
    // timestamps now known (`first_token_ms` / `completed_ms`). Best-effort.
    let completed_payload = with_phases(
        captured_request.clone(),
        &serde_json::json!({
            "dispatched_ms": 0,
            "first_token_ms": timing.first_token_ms,
            "completed_ms": timing.completed_ms,
        }),
    );
    if let Err(e) = record_inference_request_async(
        session.clone(),
        call_id,
        completed_payload.clone(),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .await
    {
        tracing::warn!(error = %e, "record_inference_request (completed) failed");
    }
    // Record the single `inference_request` timeline event for this call, now
    // that the provider reported usage (Part B). The export resolves the
    // `file` name deterministically from the event's seq + short_id + call_id
    // and emits the captured body (with phase timestamps + status) for it.
    let usage_json = usage.map(|u| {
        serde_json::json!({
            "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens,
            "cached_input_tokens": u.cached_input_tokens,
            "cache_creation_input_tokens": u.cache_creation_input_tokens,
        })
    });
    if let Err(e) = session.record_event(
        crate::db::session_log::SessionEventKind::InferenceRequest,
        Some(&agent.name),
        Some(&call_id.to_string()),
        &serde_json::json!({
            "usage": usage_json,
            "routing": model.routing_metadata_json(None),
        }),
    ) {
        tracing::warn!(error = %e, "record inference_request event (completed) failed");
    }

    // Assistant output text, extracted once: used both for the
    // calibration text basis below and the AssistantText emit further
    // down.
    let raw_text = extract_text(&choice);

    // Inline `<think>` handling (implementation note).
    // Reasoning is ALWAYS split off the raw text through the SAME shared
    // parser the TUI streams with — but this NEVER alters the current turn:
    // the continue-vs-end decision is driven by the raw choice's tool calls
    // (below), exactly as for a non-reasoning model. A leading `<think>` is
    // only split when it has a matching `</think>`; an unterminated one stays
    // as body under either toggle.
    //
    // Two independent rules apply post-turn:
    //
    //   Rule 1 — reasoning is NEVER replayed across turns. Whatever is
    //   classified as reasoning drove this turn but is absent from every later
    //   request's history; only body text + tool calls carry forward. It is
    //   preserved on the dedicated `reasoning` field for chip display only.
    //   Native channel reasoning (`reasoning_content`) is already dropped from
    //   the wire by `model::strip_reasoning`; inline `<think>` classified as
    //   thinking is dropped from stored history by `stored_assistant_choice`.
    //
    //   Rule 2 — the per-model/provider/global toggle (`inline_think`)
    //   CLASSIFIES a leading inline `<think>…</think>` block:
    //     ON (default): the block COUNTS AS THINKING — split off, shown as the
    //       "Thinking…" chip, and (per rule 1) dropped from later turns.
    //     OFF: the block COUNTS AS RESPONSE BODY — left inline in the body,
    //       shown as ordinary response text, carried forward like any other
    //       body text (rule 1 doesn't touch it; no chip).
    let inline_think = inline_think_enabled(&session, &cwd);
    let channel_reasoning = extract_reasoning(&choice);
    let (split_body, inline_reasoning) = crate::engine::think::split_think(&raw_text);
    // How the toggle CLASSIFIES a leading inline `<think>…</think>` block
    // (implementation note):
    //   ON  — it is THINKING: the body is the post-split answer and the
    //         block feeds the "Thinking…" chip (and is dropped from stored
    //         history by `stored_assistant_choice` so it never replays).
    //   OFF — it is RESPONSE BODY: the block stays inline in the displayed
    //         text and is carried forward like any other body text; no chip.
    // Either way an unterminated `<think>` is body (split_think leaves it).
    // `mut`: the reasoning-channel rescue (below, after `calls` is known) may
    // promote `reasoning` into `text` on a terminal turn whose answer landed in
    // the wrong channel (implementation note).
    let mut text = if inline_think {
        split_body
    } else {
        raw_text.clone()
    };
    // Native channel `reasoning_content` is always genuine reasoning, so it
    // always feeds the chip (it is already dropped from the wire by
    // `model::strip_reasoning`, never replayed — rule 1). Inline `<think>`
    // only feeds the chip when classified as thinking (toggle ON).
    let inline_chip = if inline_think {
        inline_reasoning.as_str()
    } else {
        ""
    };
    let reasoning = match (channel_reasoning.is_empty(), inline_chip.is_empty()) {
        (true, _) => inline_chip.to_string(),
        (false, true) => channel_reasoning,
        (false, false) => format!("{channel_reasoning}\n{inline_chip}"),
    };
    if let Some(u) = usage {
        if let Err(e) = record_usage_blocking(session.clone(), call_id, u).await {
            tracing::warn!(error = %e, "session.record_usage failed");
        }
        // Feed the round into tokenizer calibration only after the cheap
        // discard guards pass. Building the basis serializes the whole turn
        // history and is intentionally skipped when the sample cannot be used.
        if session.should_note_calibration_sample(u) {
            let mut basis = String::new();
            for m in history.iter() {
                if let Ok(s) = serde_json::to_string(m) {
                    basis.push_str(&s);
                }
            }
            if let Ok(s) = serde_json::to_string(&prompt) {
                basis.push_str(&s);
            }
            basis.push_str(&text);
            session.note_calibration_sample(&basis, u);
        }

        let _ = tx
            .send(TurnEvent::Usage {
                agent: agent.name.clone(),
                usage: u,
            })
            .await;
    }

    // Persist the assistant turn per the toggle's CLASSIFICATION of an inline
    // `<think>` block (`stored_assistant_choice`): ON it is thinking, so the
    // block is STRIPPED from stored history (rule 1 — reasoning never replays);
    // OFF it is response body, so the raw choice is stored verbatim and carries
    // forward. Stripping happens ONCE here, at store time — never as a
    // re-mutation of older history turns, so the cached system+history prefix
    // stays byte-stable across turns (prompt-cache safety). Channel `Reasoning`
    // blocks ride along either way and are dropped on the wire by
    // `model::strip_reasoning`.
    //
    // When the toggle is ON, a turn that strips to nothing (reasoning only, no
    // body, no tool call) collapses to `None` (`strip_think_from_choice`): we
    // drop the assistant turn rather than persist a blank `[{"text":""}]`
    // message that would poison every later request (defect B). The round's
    // `prompt` (the user/tool-result message) is always pushed; only the empty
    // assistant turn is dropped.
    let mut calls: Vec<ToolCall> = collect_tool_calls(&choice);

    // Harmony / ChatML special-token sanitizer
    // (implementation note): some local-template
    // backends (observed on gemma-4-26b-a4b via lm-studio) bleed a raw special
    // token (e.g. a bare `<|channel>`) into `text` at the channel boundary while
    // the real content went to a `tool_call`. Strip an UNAMBIGUOUS leading-marker
    // bleed artifact; prose/code citing the token is left untouched (conservative
    // scope — strong-API models never hit it). Runs BEFORE the reasoning-channel
    // rescue so a `text` that sanitizes to `""` feeds the rescue's emptiness check
    // naturally. The pre-strip content is recorded as `data.original_text` on the
    // assistant_message event below (GOALS §14 wire-vs-user split); the stripped
    // form is the SINGLE version both the user sees and the wire history carries,
    // so the model isn't re-prompted with its own broken output.
    let harmony_strip = sanitize_harmony_tokens(&text);
    let harmony_original = harmony_strip.as_ref().map(|_| text.clone());
    if let Some((stripped, stage)) = &harmony_strip {
        tracing::debug!(
            target: "engine",
            agent = %agent.name,
            stage = stage.stage(),
            "harmony sanitizer: stripped leading special-token bleed from text"
        );
        text = stripped.clone();
    }

    // Reasoning-channel rescue (implementation note):
    // a weak model whose chat template routed its FINAL answer onto the
    // reasoning channel leaves `text` empty while the real answer sits in
    // `reasoning` — the user (and, after `model::strip_reasoning` drops the
    // reasoning-only turn, the model's own later history) would see nothing.
    // Fire ONLY on a terminal, user-facing turn (`is_root && calls.is_empty()`,
    // the same boundary the user-facing answer uses below): empty `text`,
    // non-empty `reasoning`, no tool call. We then promote the verbatim
    // reasoning into `text` (prefixed with a one-line italic chip) so it is the
    // SINGLE version both the user sees and the model reads back — no dual copy
    // (GOALS §14: the reasoning was already invisible to the user, so this
    // surfaces, never rewrites). A tool-call turn (active, not answering) and a
    // whitespace-only reasoning never fire. Unconditional — no config knob.
    let reasoning_rescue = reasoning_channel_rescue(is_root, calls.is_empty(), &text, &reasoning);
    if reasoning_rescue {
        tracing::debug!(
            target: "engine",
            agent = %agent.name,
            reasoning_len = reasoning.len(),
            "reasoning-channel rescue: promoting reasoning to user-visible text"
        );
        text = promote_reasoning(&reasoning);
    }

    // Wire-history form. Normally derived from the provider's `choice` (an
    // inline-`<think>` body is stripped when the toggle classifies it as
    // thinking). On a reasoning-channel rescue we instead store the promoted
    // text verbatim as a single `Text` part: the original `choice` carries the
    // answer only on a `Reasoning` block, which `model::strip_reasoning` drops
    // from the wire — so without this the model would never see its own answer
    // on the next turn. The promoted form is identical to the user-visible
    // `text`, keeping the wire and user transcripts in lockstep.
    let stored_choice = if reasoning_rescue {
        crate::engine::message::OneOrMany::many(vec![
            crate::engine::message::AssistantContent::text(text.clone()),
        ])
        .ok()
    } else if harmony_strip.is_some() {
        // A leading Harmony special-token bleed was stripped from `text`: rebuild
        // the wire choice with the sanitized text in place of the bled `Text`
        // part (preserving any tool call the same turn carried), so the model
        // reads back the stripped form, not its own broken output. An
        // inline-`<think>` body is irrelevant here — the bleed shape is a bare
        // marker, never a `<think>` block.
        crate::engine::message::replace_text_in_choice(&choice, &text)
    } else {
        stored_assistant_choice(inline_think, &choice)
    };
    history.push(prompt);
    if let Some(stored_choice) = stored_choice {
        history.push(Message::Assistant {
            id: msg_id.clone(),
            content: stored_choice,
        });
    }

    // Text-embedded tool-call recovery (implementation note):
    // a weak model that emitted its call as TEXT (a fenced block / bare JSON in
    // the assistant message) leaves the structured `tool_calls` field EMPTY —
    // recovery only ever fires in that case (a real structured call always wins
    // and the text is left alone). The structural gate + format normalization +
    // fuzzy name-repair + existence check run here; the resolved decision drives
    // whether we synthesize a real call (dispatched below through the SAME
    // validate-then-repair + permission + execution path), nudge the model
    // (`available` unknown tool), feed back an `unknown tool` result (`strict`),
    // or do nothing. `recovered_marker` keys the synthesized call's id to its
    // §14 recovery marker (text block as `original_input`, structured call as
    // wire) so the dispatch loop records it as a [`Recovery::TextEmbedded`].
    let mut recovered_markers: std::collections::HashMap<String, Recovery> =
        std::collections::HashMap::new();
    // A pending `available`-mode nudge (model-side correction) to inject into
    // history after the AssistantText is emitted, so the block surfaces to the
    // user before the system nudge. `Some((notice, nudge))`.
    let mut available_nudge: Option<(String, String)> = None;
    if should_attempt_text_recovery(calls.is_empty(), reasoning_rescue) {
        let mode = text_embedded_recovery_mode(&session, &cwd);
        match decide_text_recovery(&agent.tools, &text, mode) {
            TextRecoveryDecision::None => {}
            TextRecoveryDecision::Recovered(rec) => {
                // Surface a recovery notice so the user sees a text-form call was
                // recovered, uniformly across structural (`task`) and ordinary
                // tools — the §14 chip on the tool_call row covers ordinary
                // tools, but a structural tool returns early before any row.
                let dropped = matches!(
                    &rec.marker,
                    Recovery::TextEmbedded {
                        dropped_trailing: true,
                        ..
                    }
                );
                let mut notice = format!(
                    "Recovered a tool call `{}` the agent emitted as text.",
                    rec.call.function.name
                );
                if dropped {
                    notice.push_str(" Trailing batched entries were dropped.");
                }
                let _ = tx.send(TurnEvent::Notice { text: notice }).await;
                append_tool_call_to_last_assistant(history, &rec.call);
                recovered_markers.insert(rec.call.id.clone(), rec.marker);
                calls.push(rec.call);
            }
            TextRecoveryDecision::UnknownStrict { call, unknown } => {
                // Inject the synthesized (unknown-named) call so the standard
                // unknown-tool failure the dispatch loop produces pairs with a
                // tool_use on the wire. No marker — the row records the natural
                // `not_in_advertised_set` rejection + hard-fail tool_result.
                append_tool_call_to_last_assistant(history, &call);
                tracing::info!(
                    target: "repair",
                    tool = %unknown,
                    "text_embedded_recovery strict: unknown tool fed back to model"
                );
                calls.push(call);
            }
            TextRecoveryDecision::UnknownAvailable {
                unknown,
                available_tools,
            } => {
                // `available` mode + unresolved name: do NOT execute. Surface a
                // yellow warning chip to the user and stage a model-side nudge so
                // it self-corrects on the next turn instead of looping.
                let notice = format!(
                    "Looks like the agent tried and failed a tool call to `{unknown}` (not an available tool)."
                );
                let nudge = unknown_tool_nudge(&unknown, &available_tools);
                available_nudge = Some((notice, nudge));
                tracing::info!(
                    target: "repair",
                    tool = %unknown,
                    "text_embedded_recovery available: unknown tool surfaced + nudged"
                );
            }
        }
    }

    // Even with streaming, emit a final AssistantText so the TUI knows
    // to freeze the live-streaming entry into a static history row.
    // Non-streaming paths land here directly. `text` is the classified body
    // (post-split when the toggle is ON, raw when OFF), `reasoning` the chip
    // text (channel + inline-when-ON), both computed above.
    //
    // We finalize whenever there is body text OR reasoning: a reasoning-only
    // turn (reasoning + a tool call, no answer) has empty `text` but, when the
    // toggle is ON, must still persist its reasoning so the thinking chip
    // survives resume and appears in exports — the TUI renders just the chip
    // (+ the tool call), never an empty bubble. When the toggle is OFF an
    // inline block is body (so it shows as text, not a chip); a body-less,
    // reasoning-less turn finalizes nothing.
    // Either way this is presentation only — the turn's continue-vs-end
    // decision is the raw `calls.is_empty()` check below, never this branch.
    if !text.trim().is_empty() || !reasoning.trim().is_empty() {
        // Outbound translation (implementation note): when this
        // is the foreground primary's *final* user-facing answer (root frame,
        // no tool calls this turn), translate the COMPLETE assembled text from
        // the model's language back into the user's. The translated form is
        // shown to the user only — the model-language `text` already went into
        // `history` (the wire/transcript split is preserved: the model sees
        // its own output, the user reads the translation) and the timeline
        // `AssistantMessage` event below records the original. When
        // translation is inactive (languages unset/equal, or the utility
        // model is unset/erroring) the text is emitted unchanged — identical
        // to the pre-feature behavior. No streaming translation: the
        // translated answer lands once, here, after the response completes.
        let shown = if is_root && calls.is_empty() && !text.trim().is_empty() {
            translate_final_response(&text, &cwd, redact.clone(), session.trusted_only_flag()).await
        } else {
            text.clone()
        };
        // Timeline event (Part B). Tagged with the same `call_id` as the
        // request that produced it so the export can group a turn. Records the
        // model's *original* (stripped) text plus its reasoning on a dedicated
        // field — the reasoning survives `/prune` / `/compact` and repopulates
        // the thinking chip on resume (rehydrate.rs), but never re-enters
        // model context. The translated user-facing form is never recorded.
        // Recorded BEFORE the `AssistantText` UI event so the assigned `seq`
        // (the message's stable id) can ride along (`pinned-messages`).
        // The event `data` is free-form JSON (`session.record_event`), so the
        // reasoning-channel rescue records its audit as a `data.recovery =
        // { kind, stage }` sub-object — NOT the tool-call `recovery_kind`/
        // `recovery_stage` columns. Those live on the `tool_call_events` table
        // and are driven by the tool-call-coupled `repair::Recovery` enum;
        // reusing them for an `assistant_message` event would require a fake
        // tool-call row or a new enum variant (schema gymnastics the spec lets
        // us avoid). The `{ kind, stage }` shape still follows the GOALS §14
        // wire-vs-user recovery naming convention.
        let mut event_data = serde_json::json!({ "text": text, "reasoning": reasoning });
        if reasoning_rescue {
            event_data["recovery"] = serde_json::json!({
                "kind": "reasoning_channel_rescue",
                "stage": "promoted",
            });
        } else if let Some((_, stage)) = &harmony_strip {
            // Harmony special-token bleed stripped: record the recovery audit and
            // preserve the pre-strip content as `data.original_text` (GOALS §14
            // wire-vs-user split, mirroring `tool_call`'s `original_input`). The
            // `text`/wire form both carry the stripped value; only this audit
            // field retains the raw bleed.
            event_data["recovery"] = serde_json::json!({
                "kind": "harmony_token_strip",
                "stage": stage.stage(),
            });
            if let Some(original) = &harmony_original {
                event_data["original_text"] = serde_json::json!(original);
            }
        }
        let seq = match session.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some(&agent.name),
            Some(&call_id.to_string()),
            &event_data,
        ) {
            Ok(seq) => Some(seq),
            Err(e) => {
                tracing::warn!(error = %e, "record assistant_message event failed");
                None
            }
        };
        let _ = tx
            .send(TurnEvent::AssistantText {
                agent: agent.name.clone(),
                text: shown,
                reasoning: reasoning.clone(),
                seq,
            })
            .await;
    }

    // `available`-mode unrecovered text call (implementation note):
    // the block was already surfaced to the user as the AssistantText above; now
    // emit the yellow warning chip (a `Notice`) and inject the model-side
    // correction nudge as a system message so the next turn steers the model to
    // re-emit a real call instead of looping. The nudge goes through the §7
    // redaction chokepoint like any other outbound content. This path does NOT
    // execute anything — it returns `Done` (the turn produced no dispatchable
    // call), and the staged system message rides into the next request.
    if let Some((notice, nudge)) = available_nudge {
        let _ = tx.send(TurnEvent::Notice { text: notice }).await;
        history.push(Message::System { content: nudge });
    }

    if calls.is_empty() {
        return Ok(TurnOutcome::Done);
    }

    // Tool dispatch.
    let ctx = ToolCtx {
        agent_id: agent.name.clone(),
        llm_mode: agent.llm_mode,
        locks,
        session: session.clone(),
        cwd: cwd.clone(),
        redact: redact.clone(),
        env_overlay: agent.env_overlay.clone(),
        interrupts,
        cancel,
        approver,
        deferred_log,
        seeds,
        has_tree: agent.tools.get("tree").is_some(),
        has_bash: agent.tools.get("bash").is_some(),
        // The blocked-`readlock` waiting indicator routes its
        // `WaitingForLock` start/clear pair back through this same turn
        // event stream (`readlock-wait-and-lock-expiry.md`).
        events: Some(tx.clone()),
        lsp,
        resource_scheduler,
    };

    // Per-call dispatch repair pipeline (fixed order, idempotent — a reorder
    // is a contract break; see `composed-repair-pipeline-idempotence.md`):
    //   1. name normalize/rebind (`repair::repair_tool_name`)
    //   2. §12 args input-repair (`repair::repair`, schema by the RESOLVED name)
    //   3. path-normalize (`repair::normalize_paths`)
    // Order is load-bearing: (2)/(3) need the name (1) resolved to look up the
    // schema. Re-running on the already-repaired call is a no-op (`Clean`).
    //
    // Whether §12 corrections are surfaced to the model as `<repair_note>`
    // lines on the wire tool_result (implementation note).
    // Resolved once per turn (model > provider > global, default off); when
    // off, behavior is exactly as before (silent canonical rewrite + user
    // chip). The user-facing transcript is never altered by this — only the
    // wire form the model reads.
    let hint_corrections = hint_tool_call_corrections_enabled(&session, &ctx.cwd);
    for tc in &calls {
        // Tool-NAME repair (implementation note), run BEFORE
        // the registry lookup and the args validate-then-repair (§12). Two
        // layers: (a) deterministically normalize a junk name and rebind it
        // to a registered tool on an exact (never fuzzy) match, so a weak
        // model emitting `read\n`/`<read>`/`functions.read`/`Read` dispatches
        // without a wasted round-trip; (b) charset-sanitize a still-unknown
        // name to `^[a-zA-Z0-9_-]{1,64}$` so the failed `tool_use` left in
        // history can't 400 the provider on replay. The structural tools
        // below (`task`/`schedule`/`handoff`/`spawn`/`done`) are
        // registered in the toolbox, so a rebind resolves them here and they
        // route correctly. `resolved_name` is the wire/model form; the
        // original (malformed) name rides `name_recovery` for the §14
        // wire-vs-user split. A clean exact match is a zero-cost passthrough
        // (`Recovery::Clean`, byte-identical to today).
        let known: Vec<&str> = active_tools.names();
        let name_repair = repair::repair_tool_name(&tc.function.name, &known);
        let resolved_name = name_repair.name.as_str();
        let name_recovery = name_repair.recovery;

        match phase_10_dispatch_one_call(agent, &session, &cwd, tx, tc, resolved_name).await? {
            ControlFlow::Break(outcome) => return Ok(outcome),
            ControlFlow::Continue(()) => {}
        }

        let mut args = tc.function.arguments.clone();
        // §14 wire-vs-user split for a text-recovered call: the user-facing
        // `original_input` is the model's exact text block (carried on the
        // recovery marker), not the lifted args — so the timeline shows the
        // text the model actually emitted with the recovery chip, while the
        // wire/model form is the structured call. For an ordinary structured
        // call `original` stays the args as before.
        let text_recovery_marker = recovered_markers.remove(&tc.id);
        let original = match &text_recovery_marker {
            Some(Recovery::TextEmbedded { original, .. }) => Value::String(original.clone()),
            _ => args.clone(),
        };

        // Validate-then-repair against the tool's own JSON Schema (§12).
        // Looked up by the NAME-repaired `resolved_name`, so a rebound junk
        // name finds the registered tool's schema and the args repair below
        // runs against it — name-repair strictly precedes args-repair. A
        // still-unknown name (no rebind, or a sanitized name) has no schema,
        // so it validates trivially and surfaces its "unknown tool" error in
        // `dispatch_one` as before — now with a provider-valid name.
        // Clean input is returned untouched; a repairable malformation is
        // fixed at the disagreeing path and re-validated; an unrecoverable
        // call short-circuits to a model-readable hard-fail *without*
        // dispatching the tool.
        let schema = agent
            .tools
            .get(resolved_name)
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let mut repair_outcome = repair(&mut args, &schema, resolved_name);
        // §12 repair telemetry (implementation note):
        // emit the shape fingerprint + issue codes + received-key summary +
        // fired rules WITH the active model/provider — the load-bearing
        // dimension (`repair()` itself is model-blind). Emitted here, where
        // `model` is in scope, on BOTH a recovered repair and an unrepairable
        // hard-fail; `None` on a clean pass (nothing malformed to fingerprint).
        // `shape_fingerprint` is also persisted on the audit row below so
        // `cockpit debug failed-calls` can group/count by model + fingerprint.
        // Telemetry must never alter dispatch — it is read-only here.
        let repair_fingerprint: Option<String> = repair_outcome.telemetry.as_ref().map(|t| {
            let model_id = model.model_id_ref();
            let provider_id = model.provider_id();
            if repair_outcome.valid {
                tracing::info!(
                    target: "repair",
                    tool = resolved_name,
                    model = model_id,
                    provider = provider_id,
                    shape_fingerprint = %t.shape_fingerprint,
                    issue_codes = %t.issue_codes_csv(),
                    received_keys = %t.received_keys_csv(),
                    rules_fired = %t.rules_fired_csv(),
                    "tool_input_repaired"
                );
            } else {
                tracing::warn!(
                    target: "repair",
                    tool = resolved_name,
                    model = model_id,
                    provider = provider_id,
                    shape_fingerprint = %t.shape_fingerprint,
                    issue_codes = %t.issue_codes_csv(),
                    received_keys = %t.received_keys_csv(),
                    rules_fired = %t.rules_fired_csv(),
                    error = repair_outcome.error.as_deref().unwrap_or(""),
                    "tool_input_invalid"
                );
            }
            t.shape_fingerprint.clone()
        });
        // Model-facing §12 correction hints, captured before `repair_outcome`
        // is decomposed below. Surfaced as `<repair_note>` lines on the WIRE
        // tool_result only when `hint_corrections` is enabled
        // (implementation note); the user transcript is
        // never altered. Empty on a clean/unrecoverable call.
        let repair_hints: Vec<String> = if hint_corrections {
            std::mem::take(&mut repair_outcome.hints)
        } else {
            Vec::new()
        };
        // The recorded recovery for the row (single-Recovery invariant, §14).
        // A name repair is the primary correction when it fired — without it
        // the call wouldn't dispatch at all — so it stands as the row's
        // recovery; the args shape-repair / path-normalize below only fill in
        // when the name was clean. The args are still repaired in `args`
        // regardless; only the *recorded* recovery is gated.
        // Text-embedded recovery is the primary correction when it fired: the
        // call wouldn't have dispatched at all without it (same rationale as a
        // name repair), so the `TextEmbedded` marker stands as the row's
        // recovery — ahead of any args shape-repair the lifted block then
        // needed. The args are still repaired in `args` regardless.
        let mut recovery = if let Some(marker) = text_recovery_marker {
            marker
        } else if matches!(name_recovery, Recovery::Clean) {
            repair_outcome.recovery
        } else {
            name_recovery
        };

        // Fabricated-absolute-path normalization (§12). Runs only on a
        // schema-valid call (the path fields are strings), and *before* the
        // sandbox / native-tool cwd-confinement checks below — it salvages a
        // fabricated absolute prefix into the matching project-root-relative
        // path (recorded as a shape repair, so the §14 wire/user split shows
        // the canonical path with a recovery chip) or hard-fails an absolute
        // path that neither exists nor salvages, with a model-legible error.
        // A salvage only overwrites a `Clean` recovery — a shape repair the
        // catalog already recorded (or a name repair) stays the primary
        // recovery for the row.
        // Set when the §12 path-normalize pass turned the call away because an
        // `x-cockpit-kind: path` field pointed at a path that does not exist
        // (model path-hallucination, e.g. a guessed `README.md`). It earns its
        // OWN rejection reason (`path_not_found`) below so repair-layer
        // telemetry isn't polluted by hallucinated paths, distinct from a
        // genuine `schema_invalid_unrepairable`.
        let mut path_not_found = false;
        if repair_outcome.valid {
            let norm = repair::normalize_paths(&mut args, &schema, &ctx.cwd);
            if let Some(err) = norm.error {
                repair_outcome.valid = false;
                path_not_found = norm.not_found;
                // Steer mid-turn: a nonexistent path is best recovered by
                // listing what actually exists. Point at `tree` when the agent
                // holds it (every file-capable primary/subagent does); fall
                // back to the generic repair-layer diagnostic otherwise.
                repair_outcome.error = Some(if path_not_found && ctx.has_tree {
                    format!(
                        "Error: `{}` does not exist; run `tree` to see existing files before reading.",
                        args.get("path").and_then(Value::as_str).unwrap_or_default()
                    )
                } else {
                    err
                });
            } else if matches!(recovery, Recovery::Clean) {
                recovery = norm.recovery;
            }
        }

        // Liveness refresh (`readlock-wait-and-lock-expiry.md`): every tool
        // call by this `(session, agent)` pushes back the idle-expiry
        // deadline of the locks it holds, so an agent legitimately mid-task
        // never loses a lock to the sweeper. One central refresh here, not
        // per-tool — it covers every dispatched call uniformly.
        ctx.locks.touch_holder(&ctx.agent_id, ctx.session.id);

        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent.name.clone(),
                call_id: tc.id.clone(),
                tool: resolved_name.to_string(),
                args: args.clone(),
            })
            .await;

        // Loop guard (GOALS §1/§12): block a back-to-back identical tool
        // call (same name + canonical post-repair `wire_input`) pending
        // approval. Only schema-valid calls are guarded — a malformed call
        // already short-circuits below, and isn't a "loop" worth
        // prompting on. The chain is maintained on `session` so it spans
        // turns; an intervening different call resets the count. When the
        // guard rejects (one-off, an always-reject rule, or headless), the
        // call is *not* dispatched and a guidance error stands in as the
        // tool result so the model changes course. With no approver wired
        // (seed-tool re-exec, tool tests) the guard is skipped — never
        // silently denied, matching the command/path approval contract.
        // `loop_guard_reject` gates dispatch; `loop_guard_count` is the live
        // consecutive-repeat count of the rejected `(tool, args)` run, carried
        // to the wire-history collapse site (`loop-collapse-structural-
        // dedup.md`) so the synthesized message can state "called N times".
        let mut loop_guard_count: u32 = 0;
        let call_signature = repair_outcome
            .valid
            .then(|| crate::approval::store::GrantStore::loop_signature(resolved_name, &args));
        let repeated_recoverable_tool_call = if let Some(signature) = call_signature.as_deref() {
            session.repeated_recoverable_tool_call_message(signature)
        } else {
            session.clear_recoverable_tool_call();
            None
        };
        let loop_guard_reject = if repeated_recoverable_tool_call.is_none()
            && repair_outcome.valid
            && let Some(approver) = ctx.approver.as_ref()
        {
            let signature = call_signature
                .as_deref()
                .expect("valid tool calls have a loop signature");
            let consecutive = session.bump_consecutive_call(signature);
            if consecutive >= loop_guard_threshold.max(1) {
                let interactive = ctx.interrupts.is_interactive_attached();
                let decision = approver
                    .approve_repeat(resolved_name, &args, interactive)
                    .await?;
                let reject = !decision.is_accept();
                if reject {
                    loop_guard_count = consecutive;
                }
                reject
            } else {
                false
            }
        } else {
            false
        };

        // Command-safety gate (implementation note):
        // in `auto` approval mode each gated call (`bash`/`webfetch`/`mcp`)
        // is judged by the utility model — with NO history —
        // before it runs. `safe` → run; `unsafe` (or utility model
        // unavailable → fail CLOSED) → escalate to the user; a denial skips
        // dispatch. The verdict also says whether the result needs a
        // post-run injection re-check (handled after dispatch). Only
        // evaluated for schema-valid, non-loop-rejected gated calls.
        let mut recheck_result = false;
        let gate_block: Option<String> = if repair_outcome.valid && !loop_guard_reject {
            match safety_gate_decision(resolved_name, &args, &ctx, tx).await {
                GateOutcome::Run { recheck } => {
                    recheck_result = recheck;
                    None
                }
                GateOutcome::Block(msg) => Some(msg),
            }
        } else {
            None
        };
        let guard = crate::config::extended::resolve_injection_guard(&ctx.cwd);
        if should_scan_tool_result(
            resolved_name,
            agent.scan_tool_results,
            session.approval_mode(),
            guard.threshold,
        ) {
            recheck_result = true;
        }

        // Dispatch only when validate-then-repair produced a schema-valid
        // call AND the loop guard didn't reject it AND the safety gate
        // didn't block it. Otherwise skip dispatch and treat the
        // model-readable diagnostic as an invocation failure — same
        // downstream audit/telemetry/history path a tool's own
        // `invalid_input` takes.
        // Rejection classification (export-audit fidelity): a call that never
        // becomes a real `tool_call` because the validate-then-repair path
        // (§12) turned it away emits a distinct `tool_rejected` event so a
        // hallucinated / unrepairable call is directly queryable. Three reasons:
        // an unrepairable malformed call (`schema_invalid_unrepairable`), a
        // path-field pointing at a nonexistent file (`path_not_found` — model
        // path-hallucination, kept distinct so it doesn't pollute repair
        // telemetry), and a name not in the agent's advertised toolbox
        // (`not_in_advertised_set`) — structural tools (`task`/`handoff`/`done`/
        // `schedule`/`spawn`/`return`) already returned above, so any unknown name
        // here is a hallucination.
        // Loop-guard / safety-gate blocks are NOT rejections in this sense (the
        // call was valid and advertised) and are not classified.
        let rejection_reason: Option<&'static str> = if loop_guard_reject || gate_block.is_some() {
            None
        } else if !repair_outcome.valid {
            // A model-hallucinated nonexistent path gets its own reason so
            // path-hallucination telemetry stays separate from genuine
            // schema-repair failures (`defensive-tool-descriptions-
            // weak-model-routing.md`).
            if path_not_found {
                Some("path_not_found")
            } else {
                Some("schema_invalid_unrepairable")
            }
        } else if active_tools.get(resolved_name).is_none() {
            Some("not_in_advertised_set")
        } else {
            None
        };
        let lifecycle_started = repair_outcome.valid && active_tools.get(resolved_name).is_some();
        if lifecycle_started {
            let (start_recovery_kind, start_recovery_stage) = recovery.db_fields();
            let start_data = serde_json::json!({
                "tool": resolved_name,
                "original_input": original.clone(),
                "wire_input": args.clone(),
                "recovery_kind": start_recovery_kind,
                "recovery_stage": start_recovery_stage,
            });
            if let Err(e) = session.record_event(
                crate::db::session_log::SessionEventKind::ToolCallStarted,
                Some(&agent.name),
                Some(&tc.id),
                &start_data,
            ) {
                tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_started event failed");
            }
        }
        let gate_blocked = gate_block.is_some();
        let repeated_recoverable_tool_call_reject = repeated_recoverable_tool_call.is_some();
        let (result, duration_ms) = if let Some(msg) = repeated_recoverable_tool_call.clone() {
            (Err(invalid_input(msg)), 0)
        } else if loop_guard_reject {
            // Loop-collapse synthesized message (`loop-collapse-
            // structural-dedup.md`): the rejection the model reads back states
            // the repeated call + attempt count + the available tool-NAME list
            // (names only — schemas would bust token economy §10 / the cache
            // prefix). It is also the message the contiguous-run collapse below
            // dedups to exactly one. The `task` enum's structural tools aren't
            // in `agent.tools`, so the list is the agent's advertised toolbox —
            // the same set the model sees in its system prompt.
            (
                Err(invalid_input(loop_guard_message(
                    resolved_name,
                    &args,
                    loop_guard_count,
                    &active_tools.names(),
                ))),
                0,
            )
        } else if let Some(msg) = gate_block {
            (Err(invalid_input(msg)), 0)
        } else if repair_outcome.valid {
            dispatch_one_timed(&active_tools, resolved_name, args.clone(), &ctx).await
        } else {
            let msg = repair_outcome
                .error
                .unwrap_or_else(|| format!("`{resolved_name}` arguments failed schema validation"));
            (Err(invalid_input(msg)), 0)
        };

        // Defensive bash-routing nudge self-suppression
        // (implementation note): a SUCCESSFUL
        // call to a dedicated file/search tool (`read`/`search`/`word`/
        // `symbol_find`/`tree`) marks that tip as adopted for the session, so a
        // later `bash` file/search command stops appending the corresponding
        // tip. Recorded once here at the single dispatch chokepoint; the `bash`
        // result-assembly site reads it. Non-tip tools record nothing.
        if result.is_ok() && crate::tools::shell_compress::tip_adopted_by(resolved_name).is_some() {
            session.record_tip_tool_used(resolved_name);
        }

        // Canonical-form history rewrite. Two layers can feed the model's
        // own corrected call back into `history` so its next inference sees
        // the shape that would have matched at stage 1:
        //
        //   - §13c tool recovery: a tool returns a recovery + canonical args
        //     (today only `editunlock`); this is authoritative because it
        //     derives the canonical form from the tool's *own execution* on
        //     already-repaired args. When present it supersedes everything —
        //     it sets the row's `wire_input_json` AND the in-history args.
        //   - §12 shape-repair fallback: when no tool recovery fired but the
        //     dispatcher's validate-then-repair pass produced a schema-valid
        //     call via a non-`Clean` stage (any of the four), we feed that
        //     repaired shape back too. Unlike §13c this fires regardless of
        //     dispatch outcome — a tool that failed for a *semantic* reason
        //     after a valid shape-repair still teaches the corrected shape,
        //     because the shape is derived purely from the schema, not from
        //     execution. `args` already holds the repaired form here.
        //
        // Tool recovery wins: the shape-repair rewrite is the fallback used
        // only when `wire_args` is `None`. Both run at the same point in the
        // turn — right after dispatch, on the just-produced assistant message
        // before it enters a cached prefix — so neither busts the prompt
        // cache beyond normal turn progression.
        let (tool_recovery, wire_args, repeat_guard) = match &result {
            Ok(out) => (
                out.recovery.clone(),
                out.canonical_args.clone(),
                out.repeat_guard.clone(),
            ),
            Err(_) => (None, None, None),
        };
        let output_sidecar = match &result {
            Ok(out) => out.output_sidecar.as_ref().map(|s| s.payload.clone()),
            Err(_) => None,
        };
        // Part B: `bash`'s sandbox-state sub-object for the tool_call event.
        // Only `bash` populates it; every other tool leaves it `None`, so the
        // event omits the `sandbox` key. Never model-facing (token economy).
        let sandbox_meta = match &result {
            Ok(out) => out.sandbox.clone(),
            Err(_) => None,
        };
        let resource_meta = match &result {
            Ok(out) => out.resource.clone(),
            Err(_) => None,
        };
        // Part (c): `bash`'s authoritative exit code for the tool_call event.
        // Only `bash` populates it; a hard-failed dispatch has no shell exit.
        let exit_code = match &result {
            Ok(out) => out.exit_code,
            Err(_) => None,
        };
        // Sandbox-unavailable detection (§6.5): when `bash` refused because the
        // sandbox can't initialize, it attached the diagnosed remedy out-of-
        // band on `unavailable_reason`. Emit a UI-only event so the daemon
        // raises a deterministic, persistent, user-facing indicator regardless
        // of what the model does. This text never enters history or any
        // inference request — it rides the event stream / broadcast bus only.
        // Per-session de-dupe lives daemon-side (the worker's forward seam), so
        // repeated failed calls don't spam the user.
        if let Some(remedy) = sandbox_meta
            .as_ref()
            .and_then(|m| m.unavailable_reason.clone())
        {
            let _ = tx.send(TurnEvent::SandboxUnavailable { remedy }).await;
        }
        // §13c tool recovery additionally rebinds `args` so the audit row's
        // `wire_input_json` is the tool's canonical form; the shape-repair
        // fallback needs no rebind (`args` is already the repaired form).
        if wire_args.is_some() {
            args = wire_args.clone().unwrap();
        }
        if let Some(canonical) =
            history_rewrite_args(wire_args.as_ref(), &args, repair_outcome.valid, &recovery)
        {
            rewrite_assistant_tool_call(history, &tc.id, canonical);
        }
        if let Some(signature) = repair_outcome
            .valid
            .then(|| crate::approval::store::GrantStore::loop_signature(resolved_name, &args))
        {
            if let Some(RepeatGuard { message }) = repeat_guard.clone() {
                session.remember_recoverable_tool_call(signature, message);
            } else if let Some(message) = repeated_recoverable_tool_call.clone() {
                session.remember_recoverable_tool_call(signature, message);
            } else {
                session.clear_recoverable_tool_call();
            }
        } else {
            session.clear_recoverable_tool_call();
        }
        // Name-repair history rewrite (implementation note):
        // when the emitted NAME was rebound or charset-sanitized, rewrite the
        // just-pushed assistant tool_call so its replayed wire form carries the
        // resolved/provider-valid name. Without this, the malformed name would
        // re-enter the next inference request and 400 the provider (Anthropic/
        // Bedrock enforce `^[a-zA-Z0-9_-]{1,64}$`) and break tool_use↔
        // tool_result pairing on a later resume. The `tool` column already
        // recorded `resolved_name`; this keeps the live history consistent.
        if matches!(recovery, Recovery::NameRepair { .. }) {
            rewrite_assistant_tool_call_name(history, &tc.id, resolved_name);
        }
        let recovery = tool_recovery.unwrap_or(recovery);

        let (raw_output, hard_fail, fail_kind) = match &result {
            Ok(ToolOutput { content, .. }) => (content.clone(), false, None),
            Err(e) => {
                let msg = format!("Error: {e}");
                (msg, true, Some(crate::engine::tool::classify_failure(e)))
            }
        };

        // Post-result hint layer (`engine::bash_hints`, `bash-result-
        // hint-layer.md`). After a successful `bash` call, run the registered
        // codebase-agnostic rules over (exit_code, stdout-empty, command, recent
        // bash history); the first match (if any) appends a `--- hint(<id>)`
        // line to the WIRE tool_result and records `data.hint` on the event
        // (wire-vs-user split, GOALS §14). The recent-history window is read
        // BEFORE this call is pushed onto the ring, so the rules see only prior
        // calls. `bash`-only — every other tool leaves `bash_hint` `None`.
        let bash_hint: Option<crate::engine::bash_hints::Hint> =
            if !hard_fail && resolved_name == "bash" {
                let command = args.get("command").and_then(Value::as_str).unwrap_or("");
                // Split the assembled `bash` body back into its stdout/stderr
                // sections so the rules see accurate streams (the `exit:`/
                // annotation lines are excluded). An empty stdout section is the
                // authoritative "result is empty" signal the thrash rule keys on.
                let (stdout, stderr) = crate::engine::bash_hints::split_bash_body(&raw_output);
                let recent = session.recent_bash();
                let ctx = crate::engine::bash_hints::BashCallContext {
                    command,
                    exit_code,
                    stdout: &stdout,
                    stderr: &stderr,
                    recent: &recent,
                };
                let hint = crate::engine::bash_hints::first_hint(&ctx);
                // Record this call into the recent-history ring AFTER reading the
                // window (so the next bash call sees it).
                session.push_recent_bash(command.to_string(), exit_code);
                hint
            } else {
                None
            };
        // The user-side `data.hint` JSON value, mirrored onto the DB row and the
        // export event. `None` when no rule fired / non-`bash` / hard-fail.
        let hint_value: Option<Value> = bash_hint.as_ref().map(|h| {
            serde_json::json!({
                "kind": h.kind,
                "text": h.user_chip.text,
                "severity": h.user_chip.severity.as_str(),
            })
        });

        // Keep tool output raw in history and the local audit row. Egress
        // redaction happens at model dispatch and at the client boundary.
        let mut output_str = raw_output;

        // Result injection re-check (implementation note):
        // when the safety gate flagged this call's result as pulling in
        // external/untrusted content, route the (scrubbed) output through
        // the shared injection-check mechanism. A `high` rating BLOCKS and
        // asks the user (allow through / drop / edit — same override UX as
        // the inbound prompt-injection block); `medium` delivers with a warn
        // chip; `low` (or unavailable → can't-recheck warn) delivers. The
        // recorded transcript keeps the post-recheck `output_str` (wire =
        // user, GOALS §14). Only fires on a successful, flagged call.
        if recheck_result && !hard_fail {
            let recheck_ctx = ResultRecheckCtx::from_tool_ctx(&ctx);
            output_str = result_recheck(&output_str, &recheck_ctx, tx).await;
        }

        if !hard_fail
            && truncated_tool_result_is_retrievable(resolved_name)
            && matches!(
                &result,
                Ok(ToolOutput {
                    truncated: true,
                    ..
                })
            )
        {
            match store_compressed_tool_result(
                &session,
                &agent.name,
                resolved_name,
                &tc.id,
                "truncated",
                &output_str,
                Some(output_str.len()),
            ) {
                Ok(hash) => {
                    output_str.push_str(&format!(
                        "\n[compressed tool result: tool={} bytes={} hash={} retrieve with tool_result_retrieve]\n",
                        resolved_name,
                        output_str.len(),
                        hash
                    ));
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tool = %resolved_name,
                        call_id = %tc.id,
                        "compressed tool result store failed"
                    );
                }
            }
        }

        if hard_fail {
            let _ = tx
                .send(TurnEvent::ToolError {
                    agent: agent.name.clone(),
                    call_id: tc.id.clone(),
                    tool: resolved_name.to_string(),
                    error: output_str.clone(),
                    kind: fail_kind.unwrap_or(crate::engine::tool::ToolFailKind::Execution),
                })
                .await;
        } else {
            let truncated = matches!(
                &result,
                Ok(ToolOutput {
                    truncated: true,
                    ..
                })
            );
            let _ = tx
                .send(TurnEvent::ToolEnd {
                    agent: agent.name.clone(),
                    call_id: tc.id.clone(),
                    tool: resolved_name.to_string(),
                    output: output_str.clone(),
                    truncated,
                    hint: bash_hint.as_ref().map(|h| h.user_chip.text.clone()),
                })
                .await;
        }

        let truncated = matches!(
            &result,
            Ok(ToolOutput {
                truncated: true,
                ..
            })
        );

        // Surface the recovery split for the timeline event (Part B):
        // the wire-vs-user inputs + recovery kind/stage make tool-input
        // corrections auditable in the export.
        let (recovery_kind, recovery_stage) = recovery.db_fields();
        let tool_path = args.get("path").and_then(Value::as_str).map(str::to_string);

        // Persist the audit row (GOALS §14 wire-vs-user split). `original`
        // is the model's exact input; `args` is the wire form — equal to the
        // original on a `Clean` call, or the canonical post-repair form when
        // a §12 shape-repair or §13c tool recovery fired. The `recovery`
        // field records which (if any) stage fired.
        // The persisted `tool` is the wire/model form (`resolved_name`): a
        // rebound junk name records the registered tool it resolved to, and a
        // sanitized still-unknown name records its provider-valid form — so on
        // resume the rehydrated assistant turn carries a name that keeps
        // tool_use↔tool_result pairing valid and can't 400 the provider. The
        // original (malformed) name rides the `recovery` (`NameRepair.original`)
        // for the §14 wire-vs-user split.
        if let Err(e) = session.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent: agent.name.clone(),
            call_id: tc.id.clone(),
            identity: crate::session::ToolCallProviderIdentity::from_provider_call(
                session.active_provider().as_deref().unwrap_or(""),
                session.active_model().as_deref().unwrap_or(""),
                tc.id.clone(),
                tc.call_id.clone(),
            ),
            tool: resolved_name.to_string(),
            path: tool_path,
            original_input_json: original.clone(),
            wire_input_json: args.clone(),
            recovery: recovery.clone(),
            hard_fail,
            exit_code,
            sandbox_enabled: sandbox_meta.as_ref().is_some_and(|m| m.enabled),
            sandboxed: sandbox_meta.as_ref().is_some_and(|m| m.confined),
            sandbox_unavailable_reason: sandbox_meta
                .as_ref()
                .and_then(|m| m.unavailable_reason.clone()),
            output: output_str.clone(),
            truncated,
            duration_ms,
            llm_mode: agent.llm_mode,
            shape_fingerprint: repair_fingerprint.clone(),
            hint: hint_value.clone(),
        }) {
            // Auditing must not break the live conversation. Log and
            // continue — the model still sees the tool result.
            tracing::warn!(error = %e, tool = %resolved_name, "persisting tool_call_event failed");
        }

        // Timeline event (Part B), sourced from / consistent with the
        // `tool_call_events` audit row above. The `call_id` here is the
        // model's per-tool-call id (`tc.id`), which is distinct from the
        // round-trip `call_id` (above) — both correlations matter. The
        // `sandbox` sub-object is present only for `bash` (Part B); it flows
        // verbatim into `events.json` on export with no exporter change.
        let mut event_data = serde_json::json!({
            "tool": resolved_name,
            "original_input": original,
            "wire_input": args,
            "recovery_kind": recovery_kind,
            "recovery_stage": recovery_stage,
            "hard_fail": hard_fail,
            "output": output_str,
            "truncated": truncated,
            "duration_ms": duration_ms,
        });
        // Name-repair surfacing (§14): when the emitted tool NAME was repaired
        // (rebound or charset-sanitized), `tool` above is the wire/model form;
        // the original malformed name (from `NameRepair.original`) rides here
        // so the user timeline can show it with the recovery chip. Present
        // only when a name repair actually fired — a clean exact name omits it.
        if let Recovery::NameRepair { original: orig, .. } = &recovery {
            event_data["original_tool"] = serde_json::json!(orig);
        }
        if let Some(meta) = &sandbox_meta
            && let Ok(meta_val) = serde_json::to_value(meta)
        {
            event_data["sandbox"] = meta_val;
        }
        if let Some(meta) = &resource_meta
            && let Ok(meta_val) = serde_json::to_value(meta)
        {
            event_data["resource"] = meta_val;
        }
        // `bash` exit code (export-audit fidelity): the authoritative structured
        // source for "which bash calls failed", so an auditor never has to regex
        // the human-readable `exit: N` line out of `output` (which is kept for
        // backward compatibility). Present only for `bash` calls that actually
        // ran a shell — `None` (key omitted) on spawn/timeout/cancel paths and
        // on every non-`bash` tool.
        if let Some(code) = exit_code {
            event_data["exit_code"] = serde_json::json!(code);
        }
        // Post-result hint (`engine::bash_hints`): the user-side `data.hint`
        // surface (`{ kind, text, severity }`), surfaced as a TUI chip and
        // ridden along on export with no schema change. Present only when a
        // rule fired on this `bash` call; the wire-side append lives on
        // `wire_output` below (wire-vs-user split, GOALS §14).
        if let Some(hint) = &hint_value {
            event_data["hint"] = hint.clone();
        }
        if let Some(sidecar) = &output_sidecar {
            event_data["output_sidecar"] = sidecar.clone();
        }
        // Rejected-call event (export-audit fidelity): emitted just BEFORE the
        // (hard-fail) `tool_call` row so a hallucinated / unrepairable call is a
        // one-query check on its own event type, not conflated with execution
        // failures. The `tool_call` row still records the diagnostic the model
        // saw; this names *why* it never dispatched.
        if let Some(reason) = rejection_reason
            && let Err(e) = session.record_tool_rejected(&agent.name, &tc.id, resolved_name, reason)
        {
            tracing::warn!(error = %e, tool = %resolved_name, "record tool_rejected event failed");
        }
        if let Err(e) = session.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some(&agent.name),
            Some(&tc.id),
            &event_data,
        ) {
            tracing::warn!(error = %e, tool = %resolved_name, "record tool_call event failed");
        }
        if lifecycle_started {
            let lifecycle_status = if repeated_recoverable_tool_call_reject {
                "blocked_recoverable_repeat_guard"
            } else if loop_guard_reject {
                "blocked_loop_guard"
            } else if gate_blocked {
                "blocked_safety_gate"
            } else if hard_fail {
                "failed"
            } else {
                "completed"
            };
            let dispatched =
                !(repeated_recoverable_tool_call_reject || loop_guard_reject || gate_blocked);
            let mut completed_data = serde_json::json!({
                "tool": resolved_name,
                "status": lifecycle_status,
                "dispatched": dispatched,
                "hard_fail": hard_fail,
                "output": event_data["output"].clone(),
                "truncated": truncated,
                "duration_ms": duration_ms,
            });
            if let Some(code) = exit_code {
                completed_data["exit_code"] = serde_json::json!(code);
            }
            if let Some(meta) = &sandbox_meta
                && let Ok(meta_val) = serde_json::to_value(meta)
            {
                completed_data["sandbox"] = meta_val;
            }
            if let Some(meta) = &resource_meta
                && let Ok(meta_val) = serde_json::to_value(meta)
            {
                completed_data["resource"] = meta_val;
            }
            if let Some(hint) = &hint_value {
                completed_data["hint"] = hint.clone();
            }
            if let Err(e) = session.record_event(
                crate::db::session_log::SessionEventKind::ToolCallCompleted,
                Some(&agent.name),
                Some(&tc.id),
                &completed_data,
            ) {
                tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_completed event failed");
            }
        }

        // §12 correction hints → the WIRE tool_result the model reads
        // (implementation note). When hinting is enabled and
        // ≥1 rule fired, each hint is prepended as a terse
        // `<repair_note>…</repair_note>` line so a weak model learns the
        // correction it would otherwise repeat. This is a wire-vs-user split on
        // the OUTPUT (§14): the user-facing `output_str` was already emitted
        // (`ToolEnd`) and persisted unchanged above; only the model's history
        // copy carries the notes. Off / no-hint → `wire_output` == `output_str`,
        // byte-identical to today.
        let mut wire_output = if repair_hints.is_empty() {
            output_str
        } else {
            let mut prefixed = String::new();
            for hint in &repair_hints {
                prefixed.push_str("<repair_note>");
                prefixed.push_str(&repair::repair_note_for_prompt(hint));
                prefixed.push_str("</repair_note>\n");
            }
            prefixed.push_str(&output_str);
            prefixed
        };
        // Failed-command verification guard → the WIRE tool_result
        // (implementation note). When a `bash`
        // command exits NON-ZERO (or is signaled — `exit_code == None` on a
        // non-hard-failed bash run), make the failure unmistakable: a prominent
        // `FAILED (exit N)` / `FAILED (signaled)` marker at the TOP of the body
        // plus a one-line non-verification nudge at the tail. Exit-code-based
        // only (no cargo/test/git keywords, no stderr heuristics — an exit-0
        // command, even with non-empty stderr, gets nothing). WIRE-side only
        // (GOALS §14): the user-facing `output_str` was already emitted/persisted
        // unchanged, the structured `exit_code` field and approval/escalation
        // logic are untouched, and the existing trailing `exit:` line stays
        // (the marker is additive). DETERMINISTIC ORDER vs the bash-hint line
        // below: marker at the head, then the original body, then the nudge,
        // then (if a hint rule fired) the `--- hint(...)` line — the nudge and
        // the hint line both survive on a failing command that also trips a
        // rule, neither clobbering the other. The marker is a plain prefix line
        // and never a `stdout:`/`stderr:`/`exit:` line, so `split_bash_body`
        // (which already ran on the un-marked `raw_output` above) is unaffected.
        if !hard_fail && resolved_name == "bash" {
            wire_output = crate::engine::bash_hints::apply_failure_guard(wire_output, exit_code);
        }
        // Post-result bash hint → the WIRE tool_result (`bash-result-
        // hint-layer.md`). After the existing `stdout:`/`stderr:`/`exit:` block
        // (and the failure guard above, if any), one blank line, then a single
        // `--- hint(<rule_id>): <wire_text>` line the model can distinguish from
        // real output. User-facing `output_str` was already emitted/persisted
        // unchanged (wire-vs-user split §14); only the model's history copy
        // carries this line. The wire_text is itself codebase-agnostic and never
        // contains a secret, but it still flows through the §7 redaction
        // chokepoint via this history → next-request path, so no extra scrub is
        // needed.
        if let Some(hint) = &bash_hint {
            if !wire_output.ends_with('\n') {
                wire_output.push('\n');
            }
            wire_output.push_str(&format!("\n--- hint({}): {}\n", hint.kind, hint.wire_text));
        }
        // Loop-collapse on the WIRE history (`loop-collapse-structural-
        // dedup.md`). When the loop guard rejected this call, the contiguous run
        // of identical rejected `(tool, args)` calls is represented by exactly
        // ONE synthesized message — `wire_output` here — instead of N. Before
        // pushing it, strip the immediately-preceding collapse pair(s) for the
        // same signature so a fresh fire UPDATES the single message's count
        // rather than appending a second (idempotence). The USER timeline and
        // the session-DB rows are untouched — each attempt was already emitted
        // (`ToolError`) and persisted (`record_tool_call`) above; this rewrites
        // only the wire projection the request builder serializes (GOALS §14).
        // This busts the prompt-cache suffix from the collapse point on cache-
        // having providers, but a thrashing model busts it anyway — escaping the
        // loop and shrinking context wins, and it is pure savings for the
        // no-cache local cohort (priority #1).
        if loop_guard_reject {
            collapse_loop_run(history, &args, resolved_name);
        }
        history.push(tool_result_message(tc, wire_output));
    }

    Ok(TurnOutcome::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ProviderEntry, ProvidersConfig};
    use rig::message::ToolFunction;

    fn test_model() -> Arc<Model> {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                ..ProviderEntry::default()
            },
        );
        Arc::new(
            Model::for_provider_with_env(
                &cfg,
                "local",
                "test-model",
                Arc::new(RedactionTable::empty()),
                |_| None,
            )
            .expect("test model builds without network"),
        )
    }

    fn test_agent() -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools: ToolBox::new(),
            model: test_model(),
            params: ModelParams::default(),
            scan_tool_results: true,
            llm_mode: crate::config::extended::LlmMode::Normal,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn test_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(Session::create(db, root.to_path_buf(), "Build").unwrap())
    }

    fn tool_call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: "call-1".to_string(),
            call_id: Some("provider-call-1".to_string()),
            function: ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    #[tokio::test]
    async fn phase_10_structural_return_breaks() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = test_agent();
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(1);
        let call = tool_call(
            "return",
            serde_json::json!({ "summary": "done", "result": "ok" }),
        );

        let flow = phase_10_dispatch_one_call(&agent, &session, tmp.path(), &tx, &call, "return")
            .await
            .unwrap();

        match flow {
            ControlFlow::Break(TurnOutcome::Return { fields }) => {
                assert_eq!(fields["summary"], "done");
                assert_eq!(fields["result"], "ok");
            }
            other => panic!("expected structural return break, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn phase_10_ordinary_tool_continues() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = test_agent();
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(1);
        let call = tool_call("read", serde_json::json!({ "path": "README.md" }));

        let flow = phase_10_dispatch_one_call(&agent, &session, tmp.path(), &tx, &call, "read")
            .await
            .unwrap();

        assert!(matches!(flow, ControlFlow::Continue(())));
    }
}
