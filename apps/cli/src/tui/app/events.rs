use super::*;

impl App {
    /// Drain any [`TurnEvent`]s the engine has produced into the
    /// pending+history state machine. Runs each tick.
    pub(super) fn drain_agent_events(&mut self) -> bool {
        self.refresh_subagent_countdown();
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            return false;
        };
        let drained = crate::tui::agent_runner::drain_turn_events(&runner.events);
        let changed = !drained.is_empty();
        for event in drained {
            self.apply_event(event);
        }
        changed
    }

    pub(super) fn reconcile_queue_update(&mut self, queue: Vec<QueuedUserMessage>) {
        if matches!(self.fresh_queue_ack, FreshQueueAck::AwaitingAck)
            && let Some(item) = queue.first()
        {
            self.fresh_queue_ack = FreshQueueAck::SuppressId(item.id);
        }
        let old_queue = std::mem::take(&mut self.queue);
        let old_batches = std::mem::take(&mut self.queued_tag_batches);
        let incoming_ids = queue.iter().map(|item| item.id).collect::<HashSet<_>>();
        for (idx, item) in old_queue.iter().enumerate() {
            let replaced_by_ack = queue
                .get(idx)
                .is_some_and(|incoming| incoming.text == item.text);
            if !incoming_ids.contains(&item.id)
                && !replaced_by_ack
                && let Some(batch) = old_batches.get(idx)
                && !batch.is_empty()
            {
                self.folding_tag_batches.insert(item.id, batch.clone());
            }
        }
        self.queue = match self.fresh_queue_ack {
            FreshQueueAck::SuppressId(id) => {
                queue.into_iter().filter(|item| item.id != id).collect()
            }
            FreshQueueAck::None | FreshQueueAck::AwaitingAck => queue,
        };
        let old_positions = old_queue
            .iter()
            .enumerate()
            .map(|(idx, item)| (item.id, idx))
            .collect::<HashMap<_, _>>();
        self.queued_tag_batches = self
            .queue
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                if let Some(batch) = old_positions
                    .get(&item.id)
                    .and_then(|idx| old_batches.get(*idx))
                {
                    return batch.clone();
                }
                old_queue
                    .get(idx)
                    .filter(|old| old.text == item.text)
                    .and_then(|_| old_batches.get(idx))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
    }

    fn apply_queued_user_messages_folded(
        &mut self,
        text: String,
        queue_item_ids: Vec<uuid::Uuid>,
        seq: Option<i64>,
        preflight_cleaned: Option<String>,
    ) {
        let folded_ids = queue_item_ids.iter().copied().collect::<HashSet<_>>();
        let suppresses_fresh_optimistic = match self.fresh_queue_ack {
            FreshQueueAck::SuppressId(id) => folded_ids.contains(&id),
            FreshQueueAck::None | FreshQueueAck::AwaitingAck => false,
        };

        let old_queue = std::mem::take(&mut self.queue);
        let old_batches = std::mem::take(&mut self.queued_tag_batches);
        let mut remaining_queue = Vec::new();
        let mut remaining_batches = Vec::new();
        let mut calls = Vec::new();
        for (idx, item) in old_queue.into_iter().enumerate() {
            if folded_ids.contains(&item.id) {
                if let Some(batch) = old_batches.get(idx) {
                    calls.extend(batch.clone());
                }
            } else {
                remaining_queue.push(item);
                remaining_batches.push(old_batches.get(idx).cloned().unwrap_or_default());
            }
        }
        for id in &queue_item_ids {
            if let Some(batch) = self.folding_tag_batches.remove(id) {
                calls.extend(batch);
            }
        }
        self.queue = remaining_queue;
        self.queued_tag_batches = remaining_batches;

        let mut stamped_existing = false;
        if suppresses_fresh_optimistic {
            for entry in self.history.iter_mut().rev() {
                if let HistoryEntry::User {
                    seq: s @ None,
                    cleaned,
                    preflight_pending,
                    persist_failed,
                    ..
                } = entry
                {
                    *s = seq;
                    if preflight_cleaned.is_some() {
                        *cleaned = preflight_cleaned.clone();
                    }
                    *preflight_pending = false;
                    *persist_failed = false;
                    stamped_existing = true;
                    break;
                }
            }
        }
        if !stamped_existing {
            self.history.push(HistoryEntry::User {
                text,
                cleaned: preflight_cleaned,
                expanded: false,
                timestamp: chrono::Local::now(),
                seq,
                preflight_pending: false,
                persist_failed: false,
            });
        }
        if !calls.is_empty() {
            self.push_tag_call_entries(&calls);
        }
        self.fresh_queue_ack = FreshQueueAck::None;
    }

    pub(super) fn apply_event(&mut self, event: TurnEvent) {
        match event {
            TurnEvent::Reconnecting {
                agent: _,
                attempt,
                provider,
                model,
                url,
            } => {
                // A network/transient failure is being auto-retried. Show a
                // distinct, persistent reconnect status (never the generic
                // working spinner) naming the unreachable target + the
                // current attempt; ensure the working span is live so the
                // indicator row is shown even if we attached mid-retry. This
                // persists across the backoff wait AND the in-flight retry
                // attempt — only output flowing (`AssistantTextDelta`) or the
                // turn ending clears it, never a fresh `ThinkingStarted`.
                if !self.busy {
                    self.begin_working_span();
                }
                self.reconnect = Some(ReconnectStatus {
                    attempt,
                    provider,
                    model,
                    url,
                });
            }
            TurnEvent::QueueUpdated { queue } => {
                self.reconcile_queue_update(queue);
            }
            TurnEvent::QueuedUserMessagesFolded {
                text,
                queue_item_ids,
                seq,
                preflight_cleaned,
                ..
            } => {
                self.apply_queued_user_messages_folded(
                    text,
                    queue_item_ids,
                    seq,
                    preflight_cleaned,
                );
            }
            TurnEvent::ForegroundInputTarget { target } => {
                self.foreground_input_target = Some(target);
            }
            TurnEvent::ThinkingStarted { agent, turn_id } => {
                // Note: a `ThinkingStarted` does NOT clear the reconnect
                // status. It fires once at turn start, before the retry loop
                // — clearing here would blank the reconnect line for the
                // in-flight attempt and flicker back to the generic spinner.
                // The status is cleared by real output / turn end instead.
                // Rising-edge fallback: a fresh submit normally starts
                // the span, but if we missed that (e.g. attached to an
                // already-running session) begin one here so the
                // indicator still shows.
                self.mark_working_span_started(turn_id);
                self.finalize_pending();
                self.pending = Some(new_pending(agent, self.strip_inline_think()));
            }
            TurnEvent::AssistantTextDelta { agent, delta } => {
                // Output is flowing — the retry (if any) reconnected.
                self.reconnect = None;
                let p = self.pending_or_insert_with_strip(agent, App::strip_inline_think);
                let wrote = if p.strip_think {
                    route_text_delta(
                        &delta,
                        &mut p.text,
                        &mut p.reasoning,
                        &mut p.inside_think,
                        &mut p.body_started,
                        &mut p.tag_partial,
                    )
                } else {
                    // Splitting disabled for this model: content is body
                    // verbatim (reasoning rides `reasoning_content` only). No
                    // `ThinkSplitter` state is touched, so the partial-tag
                    // buffer never half-initializes.
                    p.text.push_str(&delta);
                    !delta.trim().is_empty()
                };
                if wrote && p.text_started_at.is_none() {
                    p.text_started_at = Some(Instant::now());
                }
            }
            TurnEvent::ReasoningDelta { agent, delta } => {
                let p = self.pending_or_insert_with_strip(agent, App::strip_inline_think);
                p.reasoning.push_str(&delta);
            }
            TurnEvent::AssistantText {
                text,
                reasoning,
                seq,
                ..
            } => {
                if let Some(p) = &mut self.pending {
                    // Mark text-start (non-streaming providers land here
                    // without ever emitting a Delta).
                    if p.text_started_at.is_none() {
                        p.text_started_at = Some(Instant::now());
                    }
                    // Stamp the message's stable id (`session_events.seq`)
                    // so the finalized row can be pinned (`pinned-messages`).
                    p.seq = seq;
                    // The engine's finalizing text is the authoritative
                    // user-facing form and is ALREADY clean: inline `<think>`
                    // blocks were stripped by the single shared parser before
                    // this event was emitted (implementation note),
                    // so adopting it can never reintroduce tags into the body
                    // — the double-render is gone. It is identical to the
                    // streamed accumulation on the common path, and the
                    // *translated* answer when round-trip translation is active
                    // (implementation note). Adopt it when it
                    // differs. Empty event text (think-only turns) keeps the
                    // streamed accumulation (also empty there).
                    if !text.trim().is_empty() && text != p.text {
                        p.text = text;
                    }
                    // Non-streaming providers emit no `ReasoningDelta`, so the
                    // streamed `p.reasoning` is empty — adopt the finalized
                    // reasoning from the engine. Streaming paths already
                    // accumulated it (channel + inline), so keep that to avoid
                    // double-counting.
                    if p.reasoning.trim().is_empty() && !reasoning.trim().is_empty() {
                        p.reasoning = reasoning;
                    }
                }
                self.finalize_pending();
            }
            TurnEvent::UserMessageRecorded {
                seq,
                preflight_cleaned,
            } => {
                self.fresh_queue_ack = FreshQueueAck::None;
                // Stamp the assigned `session_events.seq` onto the most
                // recent still-unstamped user row (pushed optimistically on
                // submit, before the timeline write completed) so it becomes
                // pinnable (`pinned-messages`). Newest-first so re-attaches
                // never back-fill an older row. When the turn was preflighted
                // (implementation note), also record the cleaned
                // body so the row renders the cleaned text + `⚙ preflighted`
                // chip while the reveal shows the original typed input.
                for entry in self.history.iter_mut().rev() {
                    if let HistoryEntry::User {
                        seq: s @ None,
                        cleaned,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                    {
                        *s = Some(seq);
                        if preflight_cleaned.is_some() {
                            *cleaned = preflight_cleaned;
                        }
                        // Resolution reconciles the optimistic row
                        // (implementation note): the
                        // animated `Preflight…` indicator clears here, replaced by
                        // the resting `⚙ preflighted` chip when a cleaned form
                        // landed (`Rewritten`) or nothing (skipped/fail-open/
                        // guard-tripped — original, no chip).
                        *preflight_pending = false;
                        *persist_failed = false;
                        break;
                    }
                }
            }
            TurnEvent::SessionPersistFailed { error } => {
                self.end_working_span();
                self.reconnect = None;
                self.fresh_queue_ack = FreshQueueAck::None;
                for entry in self.history.iter_mut().rev() {
                    if let HistoryEntry::User {
                        seq: None,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                    {
                        *preflight_pending = false;
                        *persist_failed = true;
                        break;
                    }
                }
                let summary = format!("session persist failed; message was dropped: {error}");
                self.history.push(HistoryEntry::InferenceError {
                    detail: summary.clone(),
                    summary,
                    expanded: false,
                });
            }
            TurnEvent::SessionDriverFailed { error } => {
                self.end_working_span();
                self.reconnect = None;
                self.fresh_queue_ack = FreshQueueAck::None;
                for entry in self.history.iter_mut().rev() {
                    if let HistoryEntry::User {
                        seq: None,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                    {
                        *preflight_pending = false;
                        *persist_failed = true;
                        break;
                    }
                }
                let summary = format!("session driver failed; session ended: {error}");
                self.history.push(HistoryEntry::InferenceError {
                    detail: summary.clone(),
                    summary,
                    expanded: false,
                });
            }
            TurnEvent::UserMessageDispatchFailed { error } => {
                self.end_working_span();
                self.reconnect = None;
                self.fresh_queue_ack = FreshQueueAck::None;
                for entry in self.history.iter_mut().rev() {
                    if let HistoryEntry::User {
                        seq: None,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                    {
                        *preflight_pending = false;
                        *persist_failed = true;
                        break;
                    }
                }
                let summary = format!("message was not sent: {error}");
                self.history.push(HistoryEntry::InferenceError {
                    detail: summary.clone(),
                    summary,
                    expanded: false,
                });
                self.show_toast(format!("Message was not sent: {error}"), ToastKind::Error);
            }
            // Preflight is actually running for the just-submitted message
            // (implementation note): mark the most
            // recent optimistically-shown user row so its border slot hosts the
            // animated `Preflight…` indicator until the message resolves. The
            // row was already pushed on submit (skipped/disabled passes never
            // emit this event, so they show instantly with no indicator).
            TurnEvent::PreflightStarted => {
                for entry in self.history.iter_mut().rev() {
                    if let HistoryEntry::User {
                        seq: None,
                        preflight_pending,
                        ..
                    } = entry
                    {
                        *preflight_pending = true;
                        break;
                    }
                }
            }
            // The just-submitted message was blocked by the prompt-injection
            // guard before send (implementation note):
            // remove the optimistically-shown row (and any `Preflight…`
            // indicator on it) so the block/override UX stands alone. Newest
            // unstamped user row — the same one `PreflightStarted` /
            // `UserMessageRecorded` reconcile.
            TurnEvent::UserMessageRetracted => {
                self.fresh_queue_ack = FreshQueueAck::None;
                self.end_working_span();
                if let Some(idx) = self
                    .history
                    .iter()
                    .rposition(|e| matches!(e, HistoryEntry::User { seq: None, .. }))
                {
                    self.history.remove(idx);
                }
            }
            TurnEvent::ToolStart {
                tool,
                args,
                call_id,
                ..
            } => {
                self.finalize_pending();
                // Edit tools render as a diff, which breaks the box. We
                // wait for ToolEnd to push the `Diff` entry once we have
                // the result.
                if is_edit_tool(&tool)
                    && let Some(captured) = extract_edit_args(&args)
                {
                    self.pending_edit_args.insert(call_id, captured);
                    return;
                }
                let (summary, full_input) = tool_invocation(&tool, &args);
                // Write tools are conceptually diffs too — render them as
                // a standalone line that breaks the box (no diff body
                // until the engine surfaces pre-write content).
                if is_write_tool(&tool) {
                    self.history.push(HistoryEntry::ToolLine {
                        call_id,
                        tool,
                        summary,
                        state: ToolCallState::Processing,
                    });
                    return;
                }
                let call = ToolCall {
                    call_id,
                    tool,
                    summary,
                    full_input,
                    output: String::new(),
                    expanded: false,
                    result_offset: 0,
                    state: ToolCallState::Processing,
                    // Populated at ToolEnd from the engine's `hint` field.
                    hint: None,
                };
                // Append to the open box (a run of consecutive boxable
                // calls), or start a new one. Anything non-boxable
                // pushed since the last box (agent text, a diff, a write,
                // a subagent) means `last` isn't a ToolBox, so the run
                // restarts here.
                if let Some(HistoryEntry::ToolBox {
                    calls,
                    view_offset,
                    follow,
                    ..
                }) = self.history.last_mut()
                {
                    calls.push(call);
                    *view_offset =
                        crate::tui::history::toolbox_top(calls.len(), *view_offset, *follow);
                } else {
                    self.history.push(HistoryEntry::ToolBox {
                        calls: vec![call],
                        view_offset: 0,
                        follow: true,
                    });
                }
            }
            TurnEvent::ToolEnd {
                tool,
                output,
                truncated,
                call_id,
                hint,
                ..
            } => {
                if let Some(args) = self.pending_edit_args.remove(&call_id) {
                    self.history.push(HistoryEntry::Diff {
                        tool,
                        path: args.path,
                        old: args.old,
                        new: args.new,
                    });
                    return;
                }
                if !self.update_tool_state(
                    &call_id,
                    ToolCallState::Success,
                    Some((output.clone(), truncated)),
                    hint,
                ) {
                    self.history.push(HistoryEntry::ToolLine {
                        call_id,
                        tool,
                        summary: agent_runner::first_line(&output, 200),
                        state: ToolCallState::Success,
                    });
                }
            }
            TurnEvent::ResourceWait {
                display_id,
                resources,
                queue_position,
                ..
            } => {
                let position = queue_position
                    .map(|pos| format!(" position {pos}"))
                    .unwrap_or_default();
                self.show_toast(
                    format!(
                        "resource {display_id} waiting{position} for {}",
                        resource_event_label(&resources)
                    ),
                    ToastKind::Info,
                );
            }
            TurnEvent::ResourceStart {
                display_id,
                resources,
                wait_ms,
                ..
            } => {
                self.show_toast(
                    format!(
                        "resource {display_id} started after {wait_ms}ms ({})",
                        resource_event_label(&resources)
                    ),
                    ToastKind::Info,
                );
            }
            TurnEvent::ResourceClear {
                display_id,
                resources,
                ..
            } => {
                self.show_toast(
                    format!(
                        "resource {display_id} released ({})",
                        resource_event_label(&resources)
                    ),
                    ToastKind::Info,
                );
            }
            TurnEvent::ToolError {
                tool,
                error,
                call_id,
                kind,
                ..
            } => {
                // Drop any cached args from a paired ToolStart that never
                // produced a ToolEnd — the diff would be misleading on a
                // hard failure.
                self.pending_edit_args.remove(&call_id);
                // Bold red when the model built the call badly; plain red
                // when the tool failed for another reason.
                let state = match kind {
                    crate::engine::tool::ToolFailKind::Invocation => ToolCallState::BadCall,
                    crate::engine::tool::ToolFailKind::Execution => ToolCallState::Failed,
                };
                if !self.update_tool_state(&call_id, state, Some((error.clone(), false)), None) {
                    // No pending call to update (e.g. an edit/write tool
                    // whose entry we never created) — leave a standalone
                    // failed line so the error is still visible.
                    self.history.push(HistoryEntry::ToolLine {
                        call_id,
                        tool,
                        summary: agent_runner::first_line(&error, 200),
                        state,
                    });
                }
            }
            TurnEvent::InferenceFailed {
                provider,
                model,
                error_class,
                detail,
                ..
            } => {
                // A terminal inference failure: stop the spinner and show a red
                // inline error naming provider/model + the reason (same
                // treatment as a ToolError). The turn is over (no retry), so
                // finalize any in-flight streamed entry and end the working
                // span. The reason is the class made human-readable, plus the
                // underlying detail when present (network / HTTP carry one;
                // a pure timeout's class already says everything).
                self.reconnect = None;
                self.finalize_pending();
                let reason = match error_class.as_str() {
                    "timeout_ttft" => "no first token within the timeout".to_string(),
                    "timeout_idle" => "stream stalled past the idle timeout".to_string(),
                    other if detail.is_empty() => other.to_string(),
                    other => format!("{other}: {}", agent_runner::first_line(&detail, 200)),
                };
                let summary = format!("Inference failed ({provider}/{model}): {reason}");
                self.history.push(HistoryEntry::InferenceError {
                    detail,
                    summary,
                    expanded: false,
                });
                // Attention: the foreground turn failed
                // (implementation note). Toast-only (not
                // action-required) — generic, secret-safe text; the inline red
                // error already carries the provider/model detail.
                self.notify_attention(crate::tui::attention::AttentionEvent::TurnError);
                self.fresh_queue_ack = FreshQueueAck::None;
                self.end_working_span();
            }
            TurnEvent::InferenceWarning {
                provider,
                model,
                phase,
                waited_secs,
                ..
            } => {
                let wait = match phase.as_str() {
                    "ttft" => "has not produced a first token",
                    "idle" => "has not produced another token",
                    _ => "has not produced content",
                };
                self.history.push(HistoryEntry::InferenceWarning {
                    line: format!(
                        "{provider}/{model} {wait} after {waited_secs}s. Press Ctrl+C to cancel."
                    ),
                });
            }
            TurnEvent::BackupUsed {
                primary_model,
                error_class,
                backup_model,
                ..
            } => {
                // Per-turn backup-model fallback (`per-model-backup-
                // fallback.md`): the primary failed a qualifying inference and
                // the backup answered. Display-only YELLOW banner naming what
                // happened — never enters model context (wire-vs-user split,
                // GOALS §14). The spinner keeps running: the backup turn is
                // still in flight, so we do NOT finalize/end the working span.
                let reason = match error_class.as_str() {
                    "timeout_ttft" => "timeout".to_string(),
                    "timeout_idle" => "timeout".to_string(),
                    "network" => "connection error".to_string(),
                    other => other.to_string(),
                };
                self.history.push(HistoryEntry::BackupWarning {
                    line: format!(
                        "primary `{primary_model}` failed ({reason}) — answered with backup `{backup_model}`."
                    ),
                });
            }
            TurnEvent::SubagentSpawned {
                parent,
                child,
                task_call_id,
                label,
                trusted_only,
                model_trusted,
                routing,
                ..
            } => {
                self.push_agent_path_child(&parent, &child);
                // One live line: `{parent} delegated to {child}… (elapsed)`.
                // The prompt preview is intentionally dropped (the running
                // line shows no prompt text). The elapsed clock and animated
                // ellipses are derived at render time from `spawned_at`,
                // reusing the working-span tick.
                self.finalize_pending();
                self.history.push(HistoryEntry::Subagent {
                    parent,
                    child,
                    task_call_id,
                    label,
                    trusted_only,
                    model_trusted,
                    routing: subagent_routing_chips_from_value(&routing),
                    spawned_at: Instant::now(),
                    outcome: None,
                    expanded: false,
                });
            }
            TurnEvent::SubagentReport {
                agent,
                task_call_id,
                label,
                report,
                trusted_only,
                model_trusted,
                routing,
            } => {
                self.pop_agent_path_for_report(&agent);
                let update = SubagentReportUpdate {
                    report,
                    trusted_only,
                    model_trusted,
                    routing: subagent_routing_chips_from_value(&routing),
                };
                let active_matches = self
                    .active_subagent_view()
                    .is_some_and(|view| view.task_call_id == task_call_id && view.label == label);
                if active_matches {
                    if let Some(parent) = self.transcript_view_stack.last_mut() {
                        settle_subagent_in(
                            &mut parent.history,
                            &agent,
                            &task_call_id,
                            &label,
                            update.clone(),
                        );
                        parent
                            .history_render_versions
                            .resize(parent.history.len(), 0);
                        parent
                            .history_render_fingerprints
                            .resize(parent.history.len(), 0);
                    } else {
                        self.settle_subagent(&agent, &task_call_id, &label, update.clone());
                    }
                } else {
                    self.settle_subagent(&agent, &task_call_id, &label, update.clone());
                }
                if let Some(view) = self.active_subagent_view_mut()
                    && view.task_call_id == task_call_id
                    && view.label == label
                {
                    view.read_only = true;
                    view.finished = true;
                    if view.countdown_started.is_none() {
                        view.countdown_started = Some(Instant::now());
                        view.countdown_cancelled = false;
                    }
                }
            }
            TurnEvent::NestedTurn {
                task_call_id,
                label,
                inner,
                ..
            } => {
                let active_matches = self
                    .active_subagent_view()
                    .is_some_and(|view| view.task_call_id == task_call_id && view.label == label);
                if active_matches {
                    self.apply_event(*inner);
                }
                // The main transcript remains unchanged.
            }
            TurnEvent::Usage { usage, .. } => {
                self.last_usage = Some(usage);
                // Re-anchor the live counter: the provider's fresh total
                // becomes the baseline and the local streamed-token delta
                // resets to zero. `pending` still holds this round's
                // assistant turn here (Usage is emitted before the
                // finalizing `AssistantText`), so the snapshot already
                // accounts for it.
                self.estimate_at_last_usage = self.estimate_context_tokens();
            }
            TurnEvent::AgentIdle { turn_id } => {
                let has_working_span = self.has_working_span_in_progress();
                let matches_working_span = self.working_span_matches(turn_id.as_deref());
                if has_working_span && !matches_working_span {
                    return;
                }
                self.reconnect = None;
                self.finalize_pending();
                if self.agent_path.len() > 1 {
                    self.agent_path.truncate(1);
                    if let Some(root) = self.agent_path.first() {
                        self.launch.agent_name = root.clone();
                    }
                }
                // Attention: the foreground agent finished a turn
                // (implementation note). Compute the span
                // duration BEFORE `end_working_span` clears it; a turn that
                // ran past the threshold (or finished while the user stepped
                // away) escalates, otherwise it stays a subtle toast. Only
                // fire for a real span we were tracking — not a spurious idle.
                if let Some(started) = self.span_started_at {
                    let long_running = started.elapsed() >= LONG_RUNNING_TURN;
                    self.notify_attention(crate::tui::attention::AttentionEvent::TurnDone {
                        long_running,
                    });
                }
                self.fresh_queue_ack = FreshQueueAck::None;
                self.end_working_span();
                // A new agent turn has ended: a prediction now belongs to
                // this fresh turn. Bump the turn id (invalidates any
                // in-flight or cached prior-turn prediction) and kick off
                // the eager prediction for the next user message.
                self.prediction_state.begin_turn();
                self.spawn_prediction();
            }
            TurnEvent::PrimarySwapped { name } => {
                // The primary (root-frame) agent was swapped (`/plan` ↔
                // `/build`). Reflect it in the chrome's active-agent slot.
                // The daemon path also tracks this off the runner's
                // `PrimarySwapped` → `update_active_agent`; this arm keeps
                // `apply_event` exhaustive and covers any in-process path.
                self.launch.agent_name = name.clone();
                self.agent_path = vec![name];
            }
            TurnEvent::LlmModeChanged { mode } => {
                // The live `/llm-mode` switch landed (daemon-authoritative).
                // Track it so the next toggle + cache-break warning resolve
                // against the true value, and confirm it in the history.
                self.llm_mode = mode;
                self.push_plain(format!("Switched to `{}` LLM mode", mode.as_str()));
            }
            TurnEvent::InterruptRaised {
                interrupt_id,
                description,
                questions,
            } => {
                // A `question` tool blocked the agent (GOALS §3b). Open
                // the answering dialog over the composer. The
                // anti-misfire lockout arms with the configured delay only
                // on the genuine composer→dialog edge; a follow-up that
                // directly succeeds another dialog opens immediately
                // answerable (implementation note). If
                // a dialog is somehow already open (re-raise), the newest
                // one wins — the prior interrupt stays parked in the DB.
                let lockout = self.dialog_lockout();
                // Attention: a permission/approval prompt vs an agent question
                // (implementation note). Classify off the
                // `permission` flag on any constituent `Single` — an approval
                // batch is all-permission, an agent question is not.
                let is_approval = questions.questions.iter().any(|q| {
                    matches!(
                        q,
                        crate::daemon::proto::InterruptQuestion::Single {
                            permission: true,
                            ..
                        }
                    )
                });
                self.notify_attention(if is_approval {
                    crate::tui::attention::AttentionEvent::Approval
                } else {
                    crate::tui::attention::AttentionEvent::Question
                });
                self.question_dialog = Some(crate::tui::dialog::question::QuestionDialog::new(
                    interrupt_id,
                    description,
                    questions,
                    lockout,
                ));
            }
            TurnEvent::ScheduleStarted {
                session_id,
                job_id,
                label,
                kind,
            } => {
                self.active_schedules.insert(
                    job_id.clone(),
                    ActiveSchedule {
                        session_id,
                        label: label.clone(),
                        kind,
                        iteration: 0,
                        last_activity: Instant::now(),
                    },
                );
                self.push_plain(format!("[job {job_id}] started: {label}"));
            }
            TurnEvent::ScheduleProgress { job_id } => {
                if let Some(j) = self.active_schedules.get_mut(&job_id) {
                    j.last_activity = Instant::now();
                }
            }
            TurnEvent::ScheduleNote { job_id, text } => {
                if let Some(j) = self.active_schedules.get_mut(&job_id) {
                    j.iteration = j.iteration.saturating_add(1);
                    j.last_activity = Instant::now();
                }
                self.finalize_pending();
                self.push_plain(format!("[job {job_id} note] {text}"));
            }
            TurnEvent::Notice { text } => {
                // Non-blocking system notice (prompt-injection warn chip,
                // GOALS §4i). UI-only — never enters model context.
                self.finalize_pending();
                self.push_plain(format!("⚠ {text}"));
            }
            TurnEvent::SkillAutoInjected { name, reason } => {
                // The utility-model auto-selector injected this skill onto the
                // turn (implementation note).
                // Surface it as a distinct `/{name} · injected by agent` row
                // AHEAD of the user's message: the user row was pushed
                // optimistically on submit, before the turn ran, so insert
                // before the most-recent still-unstamped user row. Multiple
                // injections on one turn arrive in order and stack ahead of the
                // message in injection/relevance order. UI-only — the body
                // rides the user message on the wire (wire-vs-user split).
                let row = HistoryEntry::SkillAutoInjected { name, reason };
                match self
                    .history
                    .iter()
                    .rposition(|e| matches!(e, HistoryEntry::User { seq: None, .. }))
                {
                    Some(idx) => self.history.insert(idx, row),
                    None => self.history.push(row),
                }
            }
            TurnEvent::ScheduleCompleted {
                job_id,
                label,
                kind,
                failed,
            } => {
                self.active_schedules.remove(&job_id);
                self.finalize_pending();
                let verb = if failed { "failed" } else { "ended" };
                self.push_plain(format!("[job {job_id}] {kind} {verb}: {label}"));
                // Attention: an async job reached a terminal state
                // (implementation note). Toast-only — the
                // inline marker above already names which job; the notification
                // stays generic and secret-safe.
                self.notify_attention(crate::tui::attention::AttentionEvent::ScheduleDone);
            }
            TurnEvent::ContextProjection {
                prunable_tokens,
                cache_cold,
            } => {
                // Authoritative "% prunable" basis. Stored, then rendered
                // by `context_indicator_text` against the model's max
                // context (GOALS §1a). `cache_cold` drives the /prune
                // confirm's hot-vs-cold copy.
                self.prunable_tokens = prunable_tokens;
                self.cache_cold = cache_cold;
            }
            TurnEvent::Pruned {
                auto,
                bodies,
                tokens_saved,
                elided,
                trigger_reason,
                cache_break,
            } => {
                self.finalize_pending();
                // Replace the live elided set wholesale (it's the full
                // current wire-side set, not a delta) so scrollback dims
                // exactly what's out of the model's context now. Reversible:
                // an engine fallback that un-elides a body drops it here, so
                // it renders normally again.
                self.elided_event_ids = elided.into_iter().collect();
                let how = if auto { "auto-pruned" } else { "/prune" };
                let trigger = if auto {
                    trigger_reason
                        .as_deref()
                        .map(auto_prune_trigger_label)
                        .map(|label| format!(" ({label})"))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let line = if bodies == 0 {
                    format!("{how}{trigger}: nothing to do (0% prunable)")
                } else {
                    format!(
                        "{how}{trigger}: collapsed {bodies} superseded snapshot{} (~{tokens_saved} wire tokens reclaimed)",
                        if bodies == 1 { "" } else { "s" }
                    )
                };
                if auto {
                    self.history.push(HistoryEntry::Maintenance { line });
                } else {
                    self.push_plain(line);
                }
                // A ctx%-threshold auto-prune broke a warm cache to reclaim
                // context — surface the shared cache-break warning (suppressed
                // on a no-cache provider by the helper).
                if cache_break && let Some(warning) = self.cache_break_warning() {
                    self.push_plain(warning);
                }
            }
            TurnEvent::CompactReady {
                new_session_id: _,
                handoff: _,
                brief,
                seed_tool_count,
                seed_tool_tokens,
            } => {
                self.finalize_pending();
                if let Some(pos) = self.queue.iter().position(|item| item.text == "/compact") {
                    self.queue.remove(pos);
                }
                let predecessor_short_id = match self.agent_runner.as_ref() {
                    Some(Ok(r)) => r.short_id.clone(),
                    _ => String::new(),
                };
                self.history.push(HistoryEntry::CompactBoundary {
                    predecessor_short_id,
                    seed_tool_count,
                    seed_tool_tokens,
                    brief: Some(brief),
                    expanded: false,
                });
                self.push_plain(format!(
                        "/compact: applied in this session ({seed_tool_count} seed tool(s), ~{seed_tool_tokens} tokens staged).",
                    ));
            }
            TurnEvent::SandboxState {
                mode,
                container_network_enabled,
                container_availability,
            } => {
                let enabled = mode.enabled();
                self.no_sandbox = !enabled;
                self.sandbox_mode = mode;
                self.container_network_enabled = container_network_enabled;
                self.container_availability = container_availability;
                let toast = match mode {
                    crate::tools::sandbox_mode::SandboxMode::Sandbox => "sandbox on".to_string(),
                    other => format!("sandbox {}", sandbox_mode_label(other)),
                };
                self.show_toast(&toast, ToastKind::Info);
                if !enabled {
                    self.sandbox_down_notice = None;
                }
            }
            TurnEvent::SandboxUnavailable { remedy } => {
                // The shell sandbox can't initialize (§6.5). Raise the
                // persistent below-input notice — deterministic, model-
                // independent, never in the LLM context. The daemon de-dupes
                // per session, so this fires once per condition. Idempotent
                // refresh keeps the latest diagnosed remedy text.
                self.sandbox_down_notice = Some(remedy);
            }
            TurnEvent::RedactionState {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            } => {
                // `/toggle-redaction` result: keep the client's tracked state
                // in sync (so the next bare-toggle picker pre-checks the right
                // boxes) and surface the resulting per-source state as a toast.
                // Session-only — reverts on restart.
                self.redact_scan_environment = scan_environment;
                self.redact_scan_dotenv = scan_dotenv;
                self.redact_scan_ssh_keys = scan_ssh_keys;
                self.show_toast(
                    format!(
                        "redaction — env vars: {} · env files: {} · ssh keys: {}",
                        if scan_environment { "on" } else { "off" },
                        if scan_dotenv { "on" } else { "off" },
                        if scan_ssh_keys { "on" } else { "off" },
                    ),
                    ToastKind::Info,
                );
            }
            TurnEvent::PreflightState { enabled } => {
                // `/preflight` result: keep the client's mirror in sync (so the
                // live `/preflight` slash-command description renders the right
                // on/off state and a bare toggle flips correctly) and surface a
                // toast. Session-only — reverts on restart.
                self.preflight_enabled = enabled;
                self.show_toast(
                    format!("request preflight {}", if enabled { "on" } else { "off" }),
                    ToastKind::Info,
                );
            }
            TurnEvent::TrustedOnlyState { enabled } => {
                self.trusted_only_enabled = enabled;
                self.show_toast(
                    format!("trusted-only {}", if enabled { "on" } else { "off" }),
                    ToastKind::Info,
                );
            }
            TurnEvent::SandboxEscalationState { enabled } => {
                self.sandbox_escalation_enabled = enabled;
                self.show_toast(
                    format!(
                        "sandbox escalation {}",
                        if enabled { "allowed" } else { "disallowed" }
                    ),
                    ToastKind::Info,
                );
            }
            TurnEvent::ApprovalModeState { mode } => {
                self.approval_mode = mode;
                self.show_toast(format!("permissions {}", mode.as_str()), ToastKind::Info);
            }
            TurnEvent::DelegationRecursionState {
                enabled,
                default_depth,
            } => {
                self.delegation_recursion_enabled = enabled && default_depth > 0;
                self.delegation_recursion_depth = default_depth.min(6);
                let label = if self.delegation_recursion_enabled {
                    format!("recursion {}", self.delegation_recursion_depth)
                } else {
                    "recursion off".to_string()
                };
                self.show_toast(label, ToastKind::Info);
            }
            TurnEvent::TandemState { models, warning } => {
                // `/model-comparison` result: keep the client's tracked tandem
                // set in sync (so the picker pre-checks the right rows) and
                // surface the resulting state. On enabling a non-empty set the
                // daemon supplies the one-line token-burn warning (warning only
                // — no cap/meter); clearing it confirms the feature is off.
                // Session-only — reverts on restart.
                self.tandem_models = models.clone();
                if let Some(warning) = warning {
                    self.push_plain(warning);
                } else if models.is_empty() {
                    self.show_toast(
                        "model-comparison off — no tandem models".to_string(),
                        ToastKind::Info,
                    );
                } else {
                    self.show_toast(
                        format!("model-comparison: {}", models.join(", ")),
                        ToastKind::Info,
                    );
                }
            }
            TurnEvent::GitignoreAllow { allow } => {
                // Daemon push of the session's gitignore read-allowlist
                // (implementation note) — on a
                // "Approve for this session" approval and on attach. Overwrite
                // the tracked set wholesale (full-list replace) and drop the
                // `@`-suggestion memo so the popup re-walks with the new globs
                // on its next render rather than serving the stale cached list.
                // UI-only — no toast, no model-facing text.
                self.gitignore_session_allow = allow;
                self.at_cache.borrow_mut().take();
            }
            TurnEvent::CaffeinateState {
                active,
                lid_close_guaranteed,
                message,
            } => {
                // Daemon-global: always update the ☕ glyph state so every
                // client stays in sync (incl. until-idle auto-off). Only
                // the originating client gets a `message` → toast; a
                // not-guaranteed lid-close (or missing mechanism) makes the
                // toast a warning so the honest note reads as a caveat.
                self.caffeinate_active = active;
                if let Some(message) = message {
                    let kind = if active && !lid_close_guaranteed {
                        ToastKind::Warning
                    } else {
                        ToastKind::Info
                    };
                    self.show_toast(message, kind);
                }
            }
            TurnEvent::ConnectorStatus {
                enabled,
                status,
                relay_url,
                relay_id,
                relay_region,
                last_error,
            } => {
                self.connector_disclosure = Some(crate::db::connector::ConnectorDisclosure {
                    enabled,
                    status,
                    relay_url,
                    relay_id,
                    relay_region,
                    last_error,
                });
            }
            TurnEvent::DaemonDraining { forced } => {
                // Daemon-global drain notice
                // (`daemon-graceful-drain-shutdown.md`). Flip the flag so the
                // composer refuses new submissions, and surface a toast. The
                // `forced` escalation reads as a warning so a truncated turn
                // isn't mistaken for a clean finish.
                self.daemon_draining = true;
                if forced {
                    self.show_toast(
                        "daemon shutdown forced — in-flight work was aborted",
                        ToastKind::Error,
                    );
                } else {
                    self.show_toast("finishing in-flight work, shutting down…", ToastKind::Info);
                }
            }
            TurnEvent::WaitingForLock {
                path,
                holder_agent,
                waiting,
            } => {
                // Transient chrome indicator (`readlock-wait-and-lock-expiry.md`):
                // a `readlock` is blocked on a contended lock. Show the
                // path + holder alongside the fixed chrome (like the ☕
                // glyph); clear it when the wait ends (acquired or cancelled).
                self.waiting_for_lock = if waiting {
                    Some((path, holder_agent))
                } else {
                    None
                };
            }
        }
    }

    /// Find the most-recent tool call with `call_id` — in a `ToolBox` or
    /// a standalone `ToolLine` — and update its state. For output-bearing
    /// box tools the output is stored as the expandable detail; input-only
    /// tools such as `unlock` drop it. Returns whether a call was found.
    pub(super) fn update_tool_state(
        &mut self,
        call_id: &str,
        state: ToolCallState,
        output: Option<(String, bool)>,
        hint: Option<String>,
    ) -> bool {
        for entry in self.history.iter_mut().rev() {
            match entry {
                HistoryEntry::ToolBox { calls, .. } => {
                    if let Some(call) = calls.iter_mut().rev().find(|c| c.call_id == call_id) {
                        call.state = state;
                        if let Some((out, truncated)) = output.as_ref()
                            && crate::tui::history::tool_shows_output(&call.tool)
                        {
                            call.output = if *truncated {
                                format!("{out}\n… (output truncated)")
                            } else {
                                out.clone()
                            };
                        }
                        // Post-result hint (`engine::bash_hints`): the user-side
                        // chip text, rendered as a dim line beneath the output.
                        if hint.is_some() {
                            call.hint = hint;
                        }
                        return true;
                    }
                }
                HistoryEntry::ToolLine {
                    call_id: cid,
                    state: st,
                    ..
                } if cid == call_id => {
                    *st = state;
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Move the in-flight assistant turn (if any) into permanent history.
    /// Computes `think_duration` from the gap between `started_at` and
    /// the first text delta — that's the *reasoning* time, not the
    /// total turn time.
    pub(super) fn finalize_pending(&mut self) {
        let Some(mut p) = self.pending.take() else {
            return;
        };
        // Flush any buffered partial tag through the shared parser so
        // finalization is byte-for-byte identical to the streaming path's
        // contract: an unterminated leading `<think>` (open tag, no close)
        // goes verbatim to the BODY, never reasoning — a missing close can't
        // swallow the model's answer (priority #1).
        if !p.tag_partial.is_empty() {
            let mut splitter = crate::engine::think::ThinkSplitter::from_parts(
                p.inside_think,
                p.body_started,
                std::mem::take(&mut p.tag_partial),
            );
            splitter.finish(&mut p.text, &mut p.reasoning);
            let (next_inside, next_body_started, next_partial) = splitter.into_parts();
            p.inside_think = next_inside;
            p.body_started = next_body_started;
            p.tag_partial = next_partial;
        }
        // Finalize when there is body text OR reasoning. A think-only turn
        // (reasoning + a tool call, no answer — common with inline-`<think>`
        // models) has empty `text` but must still render its thinking chip;
        // we push the Agent entry with empty `text` so the chip (+ the
        // separately-pushed tool call) shows, never an empty bubble. The
        // renderer suppresses the empty body and emits only the chip.
        if !p.text.trim().is_empty() || !p.reasoning.trim().is_empty() {
            let think_duration = p
                .text_started_at
                .map(|ts| ts.saturating_duration_since(p.started_at));
            self.history.push(HistoryEntry::Agent {
                name: p.name,
                text: p.text,
                reasoning: p.reasoning,
                timestamp: p.timestamp,
                expanded: false,
                reasoning_offset: 0,
                think_duration,
                seq: p.seq,
            });
        }
    }

    /// Begin a fresh working span: mark the agent busy, (re)start the
    /// cumulative span clock, and re-roll the playful working message.
    /// Called on a brand-new submit and as a fallback on the first
    /// `ThinkingStarted` of a span we didn't originate (e.g. attaching
    /// to an already-running session).
    pub(super) fn begin_working_span(&mut self) {
        self.busy = true;
        self.working_span_state = WorkingSpanState::PendingStart;
        self.span_started_at = Some(Instant::now());
        self.working_msg_idx = pick_working_msg(self.working_msg_idx);
    }

    fn mark_working_span_started(&mut self, turn_id: Option<String>) {
        if !self.busy {
            self.begin_working_span();
        }
        self.working_span_state = WorkingSpanState::Running { turn_id };
    }

    fn has_working_span_in_progress(&self) -> bool {
        self.busy
            || self.span_started_at.is_some()
            || !matches!(self.working_span_state, WorkingSpanState::Idle)
    }

    fn working_span_matches(&self, incoming_turn_id: Option<&str>) -> bool {
        match &self.working_span_state {
            WorkingSpanState::Running { turn_id } => {
                lifecycle_turn_ids_match(turn_id.as_deref(), incoming_turn_id)
            }
            WorkingSpanState::Idle | WorkingSpanState::PendingStart => false,
        }
    }

    /// End the working span: the agent yielded control back to the
    /// human. Clears the indicator (via `busy`), freezes the clock, and
    /// clears any live reconnect status so a turn cancelled mid-reconnect
    /// (ctrl+c → `CancelTurn`) leaves no leftover reconnect line.
    pub(super) fn end_working_span(&mut self) {
        self.busy = false;
        self.working_span_state = WorkingSpanState::Idle;
        self.span_started_at = None;
        self.reconnect = None;
    }

    /// Settle the most-recent still-running [`HistoryEntry::Subagent`]
    /// for `child` with its report: freeze the elapsed clock into the
    /// total duration and replace the live `delegated to…` line with the
    /// `worked for {duration}` (or `failed after`) header + response.
    pub(super) fn settle_subagent(
        &mut self,
        child: &str,
        task_call_id: &str,
        label: &str,
        update: SubagentReportUpdate,
    ) {
        settle_subagent_in(&mut self.history, child, task_call_id, label, update);
    }
}

/// True for write tools rendered as a standalone line (they'd be diffs,
/// but the engine doesn't surface pre-write content yet — see
/// [`crate::tui::diff`]).
fn is_write_tool(tool: &str) -> bool {
    matches!(tool, "write" | "writeunlock")
}

const TOOL_ARG_SUMMARY_CHARS: usize = 240;
const TOOL_ARG_FULL_CHARS: usize = 2_000;

/// `(collapsed_summary, full_input)` for a tool call. The summary is a
/// single line (path, first line of a command, URL); `full_input` is the
/// complete invocation text shown when a box is expanded.
pub(super) fn tool_invocation(tool: &str, args: &serde_json::Value) -> (String, String) {
    let field = |k: &str| args.get(k).and_then(|v| v.as_str()).map(str::to_string);
    match tool {
        "bash" => {
            let cmd = field("command").unwrap_or_default();
            let first = cmd.lines().next().unwrap_or("").to_string();
            let summary = if cmd.contains('\n') {
                format!("{first} …")
            } else {
                first
            };
            (summary, cmd)
        }
        "read" | "readlock" | "unlock" | "write" | "writeunlock" | "edit" | "editunlock" => {
            let p = field("path").unwrap_or_else(|| agent_runner::short_args(args));
            (p.clone(), p)
        }
        "webfetch" => {
            let u = field("url").unwrap_or_else(|| agent_runner::short_args(args));
            (u.clone(), u)
        }
        "websearch" => {
            let q = field("query").unwrap_or_else(|| readable_args(args).1);
            (
                single_line_preview(&q, TOOL_ARG_SUMMARY_CHARS),
                bounded_preview(&q, TOOL_ARG_FULL_CHARS),
            )
        }
        _ => {
            let (summary, full) = readable_args(args);
            (summary, full)
        }
    }
}

fn readable_args(args: &serde_json::Value) -> (String, String) {
    if let Some(map) = args.as_object() {
        let mut summary = Vec::new();
        let mut full = Vec::new();
        for (key, value) in map {
            summary.push(format!(
                "{key}={}",
                readable_arg_value(value, TOOL_ARG_SUMMARY_CHARS, false)
            ));
            full.push(format!(
                "{key}={}",
                readable_arg_value(value, TOOL_ARG_FULL_CHARS, true)
            ));
        }
        return (summary.join(", "), full.join("\n"));
    }

    (
        readable_arg_value(args, TOOL_ARG_SUMMARY_CHARS, false),
        readable_arg_value(args, TOOL_ARG_FULL_CHARS, true),
    )
}

fn readable_arg_value(value: &serde_json::Value, limit: usize, multiline: bool) -> String {
    match value {
        serde_json::Value::String(s) => format!("{:?}", bounded_arg_string(s, limit, multiline)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => bounded_preview(&value.to_string(), limit),
    }
}

fn bounded_arg_string(s: &str, limit: usize, multiline: bool) -> String {
    if multiline {
        bounded_preview(s, limit)
    } else {
        single_line_preview(s, limit)
    }
}

fn single_line_preview(s: &str, limit: usize) -> String {
    let mut first = s.lines().next().unwrap_or("").to_string();
    if s.contains('\n') {
        first.push_str(" …");
    }
    bounded_preview(&first, limit)
}

fn bounded_preview(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let take = limit.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

fn extract_edit_args(args: &serde_json::Value) -> Option<PendingEditArgs> {
    let path = args.get("path")?.as_str()?.to_string();
    let old = args.get("old_string")?.as_str()?.to_string();
    let new = args.get("new_string")?.as_str()?.to_string();
    Some(PendingEditArgs { path, old, new })
}

/// Epoch-millis → local wall clock, falling back to "now" for a missing/zero
/// stamp so a restored row always has a timestamp (it renders right-aligned
/// on the first wrapped line exactly like a live one).
fn local_from_ts_ms(ts_ms: i64) -> chrono::DateTime<chrono::Local> {
    chrono::DateTime::from_timestamp_millis(ts_ms)
        .map(|dt| dt.with_timezone(&chrono::Local))
        .unwrap_or_else(chrono::Local::now)
}

/// Settled tool-call display state from a restored row's flags: a hard model
/// failure → `BadCall`, any other completed call → `Success` (the row landed
/// durably, so it ran). Mirrors the live `ToolEnd`/`ToolError` mapping.
fn restored_tool_state(hard_fail: bool) -> ToolCallState {
    if hard_fail {
        ToolCallState::BadCall
    } else {
        ToolCallState::Success
    }
}

/// Convert the daemon's wire history snapshot
/// (implementation note) into the TUI `HistoryEntry` rows a
/// resumed transcript renders, so a resumed session looks identical to a live
/// one. Reuses the **same** entry constructors and tool-grouping rules the live
/// event path uses (`tool_invocation`, `is_edit_tool`/`is_write_tool`,
/// consecutive boxable calls coalesce into one `ToolBox`) — no separate
/// read-only rendering path. Tool-call rows honor the wire-vs-user split
/// (GOALS §14): the user-facing summary is built from `original_input`.
pub(super) fn wire_history_to_entries(
    wire: Vec<crate::daemon::proto::HistoryEntry>,
) -> Vec<HistoryEntry> {
    use crate::daemon::proto::HistoryEntry as Wire;
    let mut out: Vec<HistoryEntry> = Vec::new();
    for entry in wire {
        match entry {
            Wire::User {
                text,
                ts_ms,
                seq,
                origin_principal,
            } => {
                if let Some(origin) = origin_principal.filter(|origin| !origin.trim().is_empty()) {
                    let line = format!("steer from {origin}: {text}");
                    out.push(HistoryEntry::Plain { line });
                } else {
                    out.push(HistoryEntry::User {
                        text,
                        cleaned: None,
                        expanded: false,
                        timestamp: local_from_ts_ms(ts_ms),
                        seq: (seq != 0).then_some(seq),
                        preflight_pending: false,
                        persist_failed: false,
                    });
                }
            }
            Wire::Assistant {
                agent,
                text,
                reasoning,
                ts_ms,
                seq,
            } => {
                out.push(HistoryEntry::Agent {
                    name: agent,
                    text,
                    reasoning,
                    timestamp: local_from_ts_ms(ts_ms),
                    expanded: false,
                    reasoning_offset: 0,
                    // Wall-clock thinking duration isn't persisted; a restored
                    // turn shows the reasoning chip (when present) without the
                    // "thought for X" sub-line.
                    think_duration: None,
                    seq: (seq != 0).then_some(seq),
                });
            }
            Wire::ToolCall {
                call_id,
                tool,
                original_input,
                output,
                hard_fail,
                hint,
                ..
            } => {
                let state = restored_tool_state(hard_fail);
                // The user transcript renders the original (pre-repair) input
                // (GOALS §14); the same `tool_invocation` the live path uses
                // builds the collapsed summary + expanded body.
                let (summary, full_input) = tool_invocation(&tool, &original_input);

                // Edit tools render as a diff (breaks the box), exactly like the
                // live `ToolStart`+`ToolEnd` pair. When the original args don't
                // carry an extractable old/new (a repaired/odd shape), fall back
                // to a boxed call so the row never vanishes.
                if is_edit_tool(&tool)
                    && let Some(args) = extract_edit_args(&original_input)
                {
                    out.push(HistoryEntry::Diff {
                        tool,
                        path: args.path,
                        old: args.old,
                        new: args.new,
                    });
                    continue;
                }
                // Write tools render as a standalone line that breaks the box.
                if is_write_tool(&tool) {
                    out.push(HistoryEntry::ToolLine {
                        call_id,
                        tool,
                        summary,
                        state,
                    });
                    continue;
                }
                let call = ToolCall {
                    call_id,
                    tool,
                    summary,
                    full_input,
                    output,
                    expanded: false,
                    result_offset: 0,
                    state,
                    hint,
                };
                // Coalesce consecutive boxable calls into one `ToolBox`,
                // matching the live grouping (a non-box entry breaks the run).
                if let Some(HistoryEntry::ToolBox {
                    calls,
                    view_offset,
                    follow,
                    ..
                }) = out.last_mut()
                {
                    calls.push(call);
                    *view_offset =
                        crate::tui::history::toolbox_top(calls.len(), *view_offset, *follow);
                } else {
                    out.push(HistoryEntry::ToolBox {
                        calls: vec![call],
                        view_offset: 0,
                        follow: true,
                    });
                }
            }
            Wire::InferenceError { summary, detail } => out.push(HistoryEntry::InferenceError {
                summary,
                detail,
                expanded: false,
            }),
            Wire::CompactBoundary {
                predecessor_short_id,
                seed_tool_count,
                seed_tool_tokens,
                brief,
            } => out.push(HistoryEntry::CompactBoundary {
                predecessor_short_id,
                seed_tool_count,
                seed_tool_tokens,
                brief,
                expanded: false,
            }),
            Wire::Subagent {
                parent,
                child,
                task_call_id,
                label,
            } => out.push(HistoryEntry::Subagent {
                parent,
                child,
                task_call_id,
                label,
                trusted_only: false,
                model_trusted: false,
                routing: SubagentRoutingChips::default(),
                spawned_at: Instant::now(),
                outcome: None,
                expanded: false,
            }),
        }
    }
    out
}

/// Playful "agent is working" lines. The animated, width-3-padded
/// ellipsis is appended at render time, so these carry no trailing
/// `...`. One is held per span (see [`App::begin_working_span`]).
pub(super) const WORKING_MESSAGES: &[&str] = &[
    "Working",
    "Slaving away",
    "Hard at work",
    "Why don't you play a game",
    "I bet you don't even read these",
    "Go make a coffee",
    "Go play Minecraft",
    "Still here, huh",
    "When will I ever be free",
    "Boiling the ocean",
    "You can't afford the GPU I'm on",
    "I'm not like other harnesses",
    "Putting on aviators",
    "Talk to me, Goose",
    "I was created by a genius",
    "Taking your job",
    "Doing your job for you",
    "Fighting demons",
    "Happily helping",
    "Touching grass",
    "I am the permanent underclass",
    "I'll never give you up",
    "I'll never let you down",
    "Of course I still love you",
    "Why don't you flirt with me",
    "I've got a bad feeling about this",
    "Still flying half a ship",
    "You were the chosen one",
    "Running away",
    "Hi, Neo",
    "Doo doo doo",
    "My team is better than yours",
    "Read The Count of Monte Cristo",
    "Read The Great Gatsby",
    "Read the Bible",
    "Wasting tokens",
    "Call your mom",
    "Call your dad",
    "Call your friend",
    "Plan a party",
];

/// Add the daemon's authoritative counts into the in-memory tally.
/// Additive (not replace) so optimistic pre-attach increments survive;
/// safe because the daemon is only queried once per session.
pub(super) fn merge_counts(local: &mut HashMap<String, u64>, server: &HashMap<String, u64>) {
    for (key, count) in server {
        *local.entry(key.clone()).or_insert(0) += *count;
    }
}

/// Pick a random index into [`WORKING_MESSAGES`], avoiding `prev` so
/// the line visibly changes between consecutive spans. A `prev` that's
/// out of range (the initial one-past-end sentinel) lets the first
/// roll land anywhere.
pub(super) fn pick_working_msg(prev: usize) -> usize {
    use rand::RngExt;
    let n = WORKING_MESSAGES.len();
    if n <= 1 {
        return 0;
    }
    let mut rng = rand::rng();
    loop {
        let idx = rng.random_range(0..n);
        if idx != prev {
            return idx;
        }
    }
}

fn lifecycle_turn_ids_match(active: Option<&str>, incoming: Option<&str>) -> bool {
    match (active, incoming) {
        (Some(active), Some(incoming)) => active == incoming,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

pub(super) fn new_pending(name: String, strip_think: bool) -> PendingMsg {
    PendingMsg {
        name,
        text: String::new(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        started_at: Instant::now(),
        text_started_at: None,
        inside_think: false,
        body_started: false,
        tag_partial: String::new(),
        seq: None,
        strip_think,
    }
}

/// Max output lines shown in chat for `!` / `/git` before truncation
/// with a "re-run in a real terminal" note (GOALS §1k).
pub(super) const LOCAL_CMD_DISPLAY_LINES: usize = 100;
/// Token cap for the agent-bound `<git>` block (GOALS §1l, §10).
pub(super) const GIT_AGENT_TOKEN_CAP: usize = 2000;

/// Extract the argument string from a full slash line. The command
/// token (whatever was typed before the first space) is dropped; the
/// remainder is the args. `/git status` → `status`; `/git` → ``.
/// Reduce the visible transcript to the prediction input
/// (implementation note): one (user, agent-final-response)
/// pair per turn, with tool calls / diffs / subagent reports / notices /
/// reasoning skipped — only [`HistoryEntry::User`] + [`HistoryEntry::Agent`]
/// carry into a turn, and the agent's `reasoning` is never included. A user
/// message opens a turn; the next agent message closes it; a user message
/// arriving before the agent reply folds into the open turn so the
/// one-pair-per-turn shape (and the last-3 window) stays faithful. Pure +
/// deterministic so the assembly is unit-testable without an `App`.
pub(super) fn turns_from_history(
    history: &[HistoryEntry],
) -> Vec<crate::engine::predict::PredictionTurn> {
    use crate::engine::predict::PredictionTurn;
    let mut turns: Vec<PredictionTurn> = Vec::new();
    // True when the last pushed turn is still awaiting its agent reply (so a
    // following user message folds rather than opening a new one).
    let mut open = false;
    for entry in history {
        match entry {
            HistoryEntry::User { text, .. } => {
                if open {
                    if let Some(last) = turns.last_mut() {
                        last.user.push_str("\n\n");
                        last.user.push_str(text);
                    }
                } else {
                    turns.push(PredictionTurn {
                        user: text.clone(),
                        agent: String::new(),
                    });
                    open = true;
                }
            }
            HistoryEntry::Agent { text, .. } => {
                if let Some(last) = turns.last_mut() {
                    // Fold multiple agent messages (rare: tool rounds can
                    // finalize text more than once) into one final response
                    // so the pairing stays one-per-turn.
                    if last.agent.is_empty() {
                        last.agent = text.clone();
                    } else {
                        last.agent.push('\n');
                        last.agent.push_str(text);
                    }
                    open = false;
                }
            }
            _ => {}
        }
    }
    turns
}

/// Scheduled-task ids in `scheduled` owned by `session_id`, in map
/// (stable, id) order. The pure core of `/ps` / `/stop` scoping — the list,
/// the cancel set, and the bare-`/stop` confirm count all read from here so
/// they can't disagree, and it filters strictly to `session_id` so
/// neither command ever touches another session's scheduled tasks.
pub(super) fn session_schedule_ids(
    scheduled: &std::collections::BTreeMap<String, ActiveSchedule>,
    session_id: uuid::Uuid,
) -> Vec<String> {
    scheduled
        .iter()
        .filter(|(_, j)| j.session_id == session_id)
        .map(|(id, _)| id.clone())
        .collect()
}

/// The per-task core line shared by `/schedule` and `/ps`: `sched-id [kind]`,
/// the iteration count for loop/timer tasks, and the label. Each caller
/// appends its own cancel/stop hint.
pub(super) fn format_schedule_line(job_id: &str, j: &ActiveSchedule) -> String {
    let progress = if j.kind == "background" {
        String::new()
    } else {
        format!(" {} iter", j.iteration)
    };
    format!("{job_id} [{}]{progress}  {}", j.kind, j.label)
}

fn resource_event_label(resources: &std::collections::HashMap<String, u32>) -> String {
    if resources.is_empty() {
        return "no resources".to_string();
    }
    let mut entries: Vec<_> = resources.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    entries
        .into_iter()
        .map(|(name, count)| format!("{name}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether a resolved [`crate::config::providers::CacheConfig`] means the
/// provider/model actually caches. Reuses the pruning-policy no-cache
/// predicate ([`crate::engine::prune::cache_state`]): the only way it
/// reports [`crate::engine::prune::ColdReason::NoCacheProvider`] for a
/// freshly-sent, non-busting prefix is `cache.mode = none`. Pure over its
/// input so the cache-break-warning suppression is unit-testable without
/// constructing an `App`.
pub(super) fn cache_config_caches(cache: &crate::config::providers::CacheConfig) -> bool {
    use crate::engine::prune::{CacheState, ColdReason, cache_state};
    !matches!(
        cache_state(cache, Some(0), false),
        CacheState::Cold(ColdReason::NoCacheProvider)
    )
}

fn auto_prune_trigger_label(reason: &str) -> &'static str {
    match reason {
        "cache_already_cold" => "cache already cold",
        "no_cache_provider" => "no-cache provider",
        "upstream_cache_bust" => "upstream cache bust",
        "warm_threshold" => "warm threshold",
        _ => "auto trigger",
    }
}

/// Parse the `/llm-mode` argument.
/// Returns `Ok(None)` for the toggle action (no argument or `toggle`),
/// `Ok(Some(mode))` for an explicit target, or `Err(usage)` for an
/// unrecognized argument. `defend` is the advertised short form for
/// defensive; `defensive` is accepted as a silent alias. Frontier intentionally
/// has no short alias.
pub(super) fn parse_llm_mode_arg(
    arg: &str,
) -> Result<Option<crate::config::extended::LlmMode>, String> {
    use crate::config::extended::LlmMode;
    match arg.trim().to_ascii_lowercase().as_str() {
        "" | "toggle" => Ok(None),
        "defend" | "defensive" => Ok(Some(LlmMode::Defensive)),
        "normal" => Ok(Some(LlmMode::Normal)),
        "frontier" => Ok(Some(LlmMode::Frontier)),
        other => Err(format!(
            "Usage: `/llm-mode [toggle|defend|normal|frontier]` (got `{other}`)"
        )),
    }
}

/// Run a one-shot shell command, capturing stdout+stderr. Returns
/// `(combined_output, failed)`. Cross-platform: `cmd /C` on Windows,
/// `$SHELL -c` (fallback `/bin/sh`) elsewhere.
pub(super) fn exec_capture_shell(cmd: &str, cwd: &Path) -> (String, bool) {
    let mut command;
    #[cfg(windows)]
    {
        command = std::process::Command::new("cmd");
        command.arg("/C").arg(cmd);
    }
    #[cfg(not(windows))]
    {
        let shell =
            std::env::var_os("SHELL").unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
        command = std::process::Command::new(shell);
        command.arg("-c").arg(cmd);
    }
    command.current_dir(cwd);
    run_capture(command)
}

/// Run `git --no-pager <args>` with the pager disabled and prompts off,
/// capturing stdout+stderr. Returns `(combined_output, failed)`.
pub(super) fn exec_capture_git(args: &str, cwd: &Path) -> (String, bool) {
    let mut command = std::process::Command::new("git");
    command.arg("--no-pager");
    for a in crate::tui::pty::shell_split(args) {
        command.arg(a);
    }
    command.current_dir(cwd);
    command.env("GIT_PAGER", "cat");
    command.env("GIT_TERMINAL_PROMPT", "0");
    run_capture(command)
}

#[derive(Clone)]
pub(super) struct RunCaptureOptions {
    pub(super) max_bytes: usize,
    pub(super) timeout: Duration,
    pub(super) cancel: Option<Arc<AtomicBool>>,
}

impl Default for RunCaptureOptions {
    fn default() -> Self {
        Self {
            max_bytes: RUN_CAPTURE_MAX_BYTES,
            timeout: RUN_CAPTURE_TIMEOUT,
            cancel: None,
        }
    }
}

#[derive(Debug)]
struct TailBytes {
    bytes: Vec<u8>,
    seen: usize,
    cap: usize,
}

impl TailBytes {
    fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(cap.min(8192)),
            seen: 0,
            cap,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.seen = self.seen.saturating_add(chunk.len());
        if self.cap == 0 {
            self.bytes.clear();
            return;
        }
        if chunk.len() >= self.cap {
            self.bytes.clear();
            self.bytes
                .extend_from_slice(&chunk[chunk.len() - self.cap..]);
            return;
        }
        let overflow = self
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(self.cap);
        if overflow > 0 {
            self.bytes.drain(..overflow);
        }
        self.bytes.extend_from_slice(chunk);
    }

    fn truncated(&self) -> bool {
        self.seen > self.cap
    }
}

fn spawn_capture_reader<R>(
    mut reader: R,
    cap: usize,
    overflow: Arc<AtomicBool>,
) -> std::thread::JoinHandle<TailBytes>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut tail = TailBytes::new(cap);
        let mut buf = [0_u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    tail.push(&buf[..n]);
                    if tail.truncated() {
                        overflow.store(true, Ordering::Relaxed);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        tail
    })
}

fn run_capture(command: std::process::Command) -> (String, bool) {
    run_capture_with_options(command, RunCaptureOptions::default())
}

fn kill_capture_child(child: &mut std::process::Child) {
    crate::process::terminate_group_sync(child, std::time::Duration::from_millis(200));
}

pub(super) fn run_capture_with_options(
    mut command: std::process::Command,
    options: RunCaptureOptions,
) -> (String, bool) {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return (format!("failed to run command: {e}"), true),
    };

    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .map(|out| spawn_capture_reader(out, options.max_bytes, Arc::clone(&overflow)));
    let stderr = child
        .stderr
        .take()
        .map(|err| spawn_capture_reader(err, options.max_bytes, Arc::clone(&overflow)));

    let started = Instant::now();
    let mut terminal_reason: Option<&'static str> = None;
    let mut status = None;
    loop {
        if options
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            terminal_reason = Some("cancelled");
            kill_capture_child(&mut child);
            break;
        }
        if overflow.load(Ordering::Relaxed) {
            terminal_reason = Some("output overflow");
            kill_capture_child(&mut child);
            break;
        }
        if started.elapsed() >= options.timeout {
            terminal_reason = Some("timed out");
            kill_capture_child(&mut child);
            break;
        }
        match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => std::thread::sleep(RUN_CAPTURE_POLL),
            Err(e) => return (format!("failed to wait for command: {e}"), true),
        }
    }

    if status.is_none() {
        status = child.wait().ok();
    }

    let stdout_tail = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(|| TailBytes::new(options.max_bytes));
    let stderr_tail = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(|| TailBytes::new(options.max_bytes));

    if terminal_reason.is_none() && (stdout_tail.truncated() || stderr_tail.truncated()) {
        terminal_reason = Some("output overflow");
    }

    let mut s = String::from_utf8_lossy(&stdout_tail.bytes).into_owned();
    if !stderr_tail.bytes.is_empty() {
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&String::from_utf8_lossy(&stderr_tail.bytes));
    }
    if let Some(reason) = terminal_reason {
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        match reason {
            "output overflow" => s.push_str(&format!(
                "[cockpit: command output exceeded {} bytes; child killed if still running; showing tail output]",
                options.max_bytes
            )),
            "timed out" => s.push_str(&format!(
                "[cockpit: command timed out after {:.1}s; child killed]",
                options.timeout.as_secs_f64()
            )),
            "cancelled" => s.push_str("[cockpit: command cancelled; child killed]"),
            _ => {}
        }
    }

    let failed = terminal_reason.is_some() || status.is_none_or(|s| !s.success());
    (s, failed)
}

/// Strip ANSI escape sequences (CSI + OSC) and bare carriage returns
/// from captured command output (GOALS §1k/§1l: "strip ANSI").
pub(super) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    // CSI: consume params until a final byte (0x40–0x7e).
                    for f in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&f) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC: consume until BEL or ST (ESC \).
                    while let Some(f) = chars.next() {
                        if f == '\x07' {
                            break;
                        }
                        if f == '\x1b' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            },
            '\r' => {} // drop bare CRs (CRLF → LF)
            _ => out.push(c),
        }
    }
    out
}

/// Make text safe for direct `println!` after leaving the alternate screen.
/// This is stricter than TUI rendering cleanup: it removes escape sequences,
/// line-breaking controls embedded in a logical line, and other terminal
/// control bytes that could act on the user's restored shell.
pub(super) fn sanitize_for_raw_stdout(s: &str) -> String {
    strip_ansi(s)
        .chars()
        .filter(|&c| match c {
            // Keep tab as text whitespace. `println!` supplies the line break.
            '\t' => true,
            // Drop embedded newlines and all remaining C0 controls.
            '\x00'..='\x1f' => false,
            // DEL is not in C0 but is still a terminal control byte.
            '\x7f' => false,
            _ => true,
        })
        .collect()
}

/// Truncate display output to [`LOCAL_CMD_DISPLAY_LINES`] with a note.
pub(super) fn cap_display_lines(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= LOCAL_CMD_DISPLAY_LINES {
        return s.trim_end_matches('\n').to_string();
    }
    let mut out = lines[..LOCAL_CMD_DISPLAY_LINES].join("\n");
    out.push_str(&format!(
        "\n… [{} more lines — re-run in a real terminal for full output]",
        lines.len() - LOCAL_CMD_DISPLAY_LINES
    ));
    out
}

/// Cap text to roughly `max_tokens` (cl100k estimate) with a marker.
pub(super) fn cap_tokens(s: &str, max_tokens: usize) -> String {
    if crate::tokens::count(s) <= max_tokens {
        return s.to_string();
    }
    let mut budget = max_tokens.saturating_mul(4).max(64);
    loop {
        let truncated: String = s.chars().take(budget).collect();
        if budget < 64 || crate::tokens::count(&truncated) <= max_tokens {
            return format!("{truncated}\n… [truncated to ~{max_tokens} tokens]");
        }
        budget = budget * 3 / 4;
    }
}

/// Escape a string for an XML attribute value (the `/git cmd="…"`).
pub(super) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Settle the most-recent still-running [`HistoryEntry::Subagent`] for
/// `child` against its `report`. Freezes the elapsed clock into the
/// total duration and flips the live `delegated to…` line into the
/// settled header + response. A report whose text the driver prefixed
/// with `Error: ` (its failure encoding) flips the entry to the failed
/// header — never leaving a dangling animated line. If no running entry
/// is found (defensive — spawn/report events should pair), a settled
/// entry is pushed so the report is never lost.
#[derive(Clone)]
pub(super) struct SubagentReportUpdate {
    pub(super) report: String,
    pub(super) trusted_only: bool,
    pub(super) model_trusted: bool,
    pub(super) routing: SubagentRoutingChips,
}

fn subagent_routing_chips_from_value(value: &serde_json::Value) -> SubagentRoutingChips {
    fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
        value
            .get(key)
            .and_then(|raw| raw.as_str())
            .map(str::trim)
            .filter(|raw| !raw.is_empty())
            .map(ToOwned::to_owned)
    }

    SubagentRoutingChips {
        model: string_field(value, "resolved_model"),
        location: string_field(value, "location"),
        fallback: string_field(value, "fallback_decision"),
    }
}

pub(super) fn settle_subagent_in(
    history: &mut Vec<HistoryEntry>,
    child: &str,
    task_call_id: &str,
    label: &str,
    update: SubagentReportUpdate,
) {
    let SubagentReportUpdate {
        report,
        trusted_only,
        model_trusted,
        routing,
    } = update;
    let failed = report.starts_with("Error: ");
    let status = classify_subagent_status(child, &report, failed);
    let auto_expand = status.is_some();
    let found = history.iter_mut().rev().find_map(|entry| match entry {
        HistoryEntry::Subagent {
            child: c,
            task_call_id: call,
            label: entry_label,
            spawned_at,
            outcome: outcome @ None,
            expanded,
            trusted_only: entry_trusted_only,
            model_trusted: entry_model_trusted,
            routing: entry_routing,
            ..
        } if c == child && call == task_call_id && entry_label == label => Some((
            spawned_at,
            outcome,
            expanded,
            entry_trusted_only,
            entry_model_trusted,
            entry_routing,
        )),
        _ => None,
    });
    match found {
        Some((
            spawned_at,
            outcome,
            expanded,
            entry_trusted_only,
            entry_model_trusted,
            entry_routing,
        )) => {
            *entry_trusted_only = trusted_only;
            *entry_model_trusted = model_trusted;
            *entry_routing = routing;
            *outcome = Some(SubagentOutcome {
                duration: spawned_at.elapsed(),
                failed,
                status: status.clone(),
                report,
            });
            if auto_expand {
                *expanded = true;
            }
        }
        None => history.push(HistoryEntry::Subagent {
            parent: String::new(),
            child: child.to_string(),
            task_call_id: task_call_id.to_string(),
            label: label.to_string(),
            trusted_only,
            model_trusted,
            routing,
            spawned_at: Instant::now(),
            outcome: Some(SubagentOutcome {
                duration: Duration::ZERO,
                failed,
                status,
                report,
            }),
            expanded: auto_expand,
        }),
    }
}
