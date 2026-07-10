fn forward_sandbox_unavailable(armed: &AtomicBool) -> bool {
    !armed.swap(true, Ordering::SeqCst)
}

/// Release every lock a session holds because it became unattended-while-idle
/// (implementation note). Both release edges — the
/// last-detach drop and the `AgentIdle`-with-zero-clients seam — funnel through
/// here so the snapshot/wake/persist behavior lives in exactly one place.
/// Errors are logged, never propagated: a failed release must not crash a
/// detach or a turn boundary (the idle-expiry sweep is the backstop).
fn schedule_session_locks_unattended(
    locks: Arc<LockManager>,
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(release_session_locks_unattended(
            locks, counter, live, session_id, reason,
        ));
    } else {
        std::thread::spawn(move || {
            if counter.load(Ordering::SeqCst) != 0 || live.processing() {
                return;
            }
            if let Err(e) = locks.suspend_session(session_id) {
                tracing::warn!(
                    error = %e,
                    %session_id,
                    reason,
                    "releasing session locks failed"
                );
            }
        });
    }
}

fn schedule_session_container_release(
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(release_session_container_unattended(
            counter, live, session_id, reason,
        ));
    }
}

async fn release_session_container_unattended(
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if counter.load(Ordering::SeqCst) != 0 || live.processing() || live.has_active_schedules() {
        return;
    }
    let Some(manager) = crate::container::container_manager().get() else {
        return;
    };
    if counter.load(Ordering::SeqCst) != 0 || live.processing() || live.has_active_schedules() {
        return;
    }
    if let Err(e) = manager.remove_container(session_id).await {
        tracing::warn!(error = %e, %session_id, reason, "removing idle session container failed");
    }
}

async fn release_session_locks_unattended(
    locks: Arc<LockManager>,
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if counter.load(Ordering::SeqCst) != 0 || live.processing() {
        return;
    }
    let semaphore = LOCK_SNAPSHOT_WORK
        .get_or_init(|| Arc::new(Semaphore::new(LOCK_SNAPSHOT_WORK_LIMIT)))
        .clone();
    let Ok(_permit) = semaphore.acquire_owned().await else {
        return;
    };
    if counter.load(Ordering::SeqCst) != 0 || live.processing() {
        return;
    }
    let result = tokio::task::spawn_blocking(move || locks.suspend_session(session_id)).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                %session_id,
                reason,
                "releasing session locks failed"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                %session_id,
                reason,
                "lock release blocking task failed"
            );
        }
    }
}

/// Whether the last-detach edge should release: this drop took the interactive
/// count to zero (it was `1` before) **and** the session is idle (not
/// mid-turn). A mid-turn detach is left alone — the worker keeps running and the
/// next `AgentIdle` with zero clients is the release backstop.
fn detach_should_release(prev_count: usize, processing: bool) -> bool {
    prev_count == 1 && !processing
}

fn update_live_foreground(
    foreground: &Arc<Mutex<LiveForegroundState>>,
    foreground_input_target: &Arc<Mutex<crate::engine::message::QueueTarget>>,
    event: &TurnEvent,
) {
    let mut state = foreground
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match event {
        TurnEvent::ForegroundInputTarget { target } => {
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = target.clone();
            state.foreground_target = target.clone();
            if !target.agent.is_empty() {
                if target.depth == 0 {
                    state.root_agent = target.agent.clone();
                    state.active_agent_path = vec![target.agent.clone()];
                    state.active_subagents.clear();
                } else if state
                    .active_agent_path
                    .last()
                    .map(|agent| agent != &target.agent)
                    .unwrap_or(true)
                {
                    state.active_agent_path.push(target.agent.clone());
                }
            }
        }
        TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            ..
        } => {
            if let Some(parent_idx) = state
                .active_agent_path
                .iter()
                .rposition(|agent| agent == parent)
            {
                state.active_agent_path.truncate(parent_idx + 1);
            } else {
                state.active_agent_path = vec![state.root_agent.clone()];
            }
            state.active_agent_path.push(child.clone());
            state.active_subagents.push(proto::ActiveSubagent {
                parent: parent.clone(),
                child: child.clone(),
                task_call_id: task_call_id.clone(),
                label: label.clone(),
            });
            state.foreground_target = crate::engine::message::QueueTarget::child(
                child.clone(),
                state.active_agent_path.len().saturating_sub(1),
                task_call_id.clone(),
                label.clone(),
            );
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            ..
        } => {
            if let Some(idx) = state.active_subagents.iter().rposition(|sub| {
                sub.child == *agent && sub.task_call_id == *task_call_id && sub.label == *label
            }) {
                state.active_subagents.truncate(idx);
            } else {
                state.active_subagents.pop();
            }
            if let Some(agent_idx) = state
                .active_agent_path
                .iter()
                .rposition(|name| name == agent)
            {
                state.active_agent_path.truncate(agent_idx);
            } else {
                state.active_agent_path.pop();
            }
            if state.active_agent_path.is_empty() {
                let root_agent = state.root_agent.clone();
                state.active_agent_path.push(root_agent);
            }
            if let Some(active) = state.active_subagents.last() {
                state.foreground_target = crate::engine::message::QueueTarget::child(
                    active.child.clone(),
                    state.active_agent_path.len().saturating_sub(1),
                    active.task_call_id.clone(),
                    active.label.clone(),
                );
            } else {
                state.foreground_target =
                    crate::engine::message::QueueTarget::root(state.root_agent.clone());
            }
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::PrimarySwapped { name } => {
            state.root_agent = name.clone();
            state.active_agent_path = vec![name.clone()];
            state.active_subagents.clear();
            state.foreground_target = crate::engine::message::QueueTarget::root(name.clone());
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::AgentIdle { .. } if state.active_subagents.is_empty() => {
            state.active_agent_path = vec![state.root_agent.clone()];
            state.foreground_target =
                crate::engine::message::QueueTarget::root(state.root_agent.clone());
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        _ => {}
    }
}

/// The primary agent a new session starts on: the user's configured
/// `defaultPrimaryAgent`, falling back to `Auto` (the conversational
/// front-door router) when unset. The registry uses this when it
/// constructs a fresh session row; the worker uses it for the approver's
/// prompt-attribution agent. Lives here so the constants and
/// event-translation helpers stay in one module.
pub(crate) fn initial_active_agent(cfg: &crate::config::extended::ExtendedConfig) -> &'static str {
    let configured = cfg.default_primary_agent.agent_name();
    // Experimental-mode gate (implementation note): with
    // the flag off, a configured default that points at a gated builtin
    // (`Auto`/`Plan`/…) silently falls back to `Build`. Returning `&'static
    // str` keeps the existing signature: both the configured names and the
    // fallback are statics, so resolve to the canonical static rather than a
    // heap string.
    if !cfg.experimental_mode && crate::agents::is_experimental_primary(configured) {
        crate::agents::FALLBACK_PRIMARY
    } else {
        configured
    }
}

