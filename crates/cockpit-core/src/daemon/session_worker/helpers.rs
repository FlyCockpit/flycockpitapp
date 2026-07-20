fn steer_delegation_side_channel(
    session: &Session,
    _redact: &RedactionTable,
    task_call_id: String,
    label: String,
    message: String,
    origin_principal: String,
) -> proto::DelegationSteerResult {
    if message.trim().is_empty() {
        return proto::DelegationSteerResult::not_steerable(
            task_call_id,
            Some(label),
            "message is required for steer".to_string(),
        );
    }
    let rows = match session.db.list_task_delegation_children(session.id) {
        Ok(rows) => rows,
        Err(error) => {
            return proto::DelegationSteerResult::internal(format!(
                "could not load task delegations: {error:#}"
            ));
        }
    };
    let matches = rows
        .iter()
        .filter(|row| row.task_call_id == task_call_id && row.label == label)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        let reason = if matches.is_empty() {
            "unknown delegation child"
        } else {
            "steer requires exactly one delegation child"
        };
        return proto::DelegationSteerResult::not_steerable(
            task_call_id,
            Some(label),
            reason.to_string(),
        );
    }
    let row = matches[0];
    if row.status != crate::db::task_delegations::DelegationStatus::Running {
        return proto::DelegationSteerResult::not_steerable(
            row.task_call_id.clone(),
            Some(row.label.clone()),
            format!("child is {}", row.status.as_str()),
        );
    }
    if message.trim().is_empty() {
        return proto::DelegationSteerResult::not_steerable(
            row.task_call_id.clone(),
            Some(row.label.clone()),
            "message is required for steer".to_string(),
        );
    }
    match session.db.enqueue_task_delegation_steer(
        &row.task_call_id,
        &row.label,
        &message,
        &origin_principal,
    ) {
        Ok(()) => proto::DelegationSteerResult::queued(
            row.task_call_id.clone(),
            row.label.clone(),
            row.pending_steers + 1,
            origin_principal,
            true,
        ),
        Err(error) => {
            proto::DelegationSteerResult::internal(format!("could not persist steer: {error:#}"))
        }
    }
}

fn queue_item_to_proto(item: crate::engine::message::QueuedUserMessage) -> proto::QueueItem {
    proto::QueueItem {
        id: item.id,
        status: match item.status {
            crate::engine::message::QueueItemStatus::Queued => proto::QueueItemStatus::Queued,
            crate::engine::message::QueueItemStatus::Folding => proto::QueueItemStatus::Folding,
        },
        text: item.text,
        display_text: item.display_text,
        target: queue_target_to_proto(item.target),
    }
}

fn remove_reason_to_proto(
    result: crate::engine::message::RemoveQueuedMessageResult,
) -> proto::RemoveQueuedUserMessageReason {
    match result {
        crate::engine::message::RemoveQueuedMessageResult::Removed => {
            proto::RemoveQueuedUserMessageReason::Removed
        }
        crate::engine::message::RemoveQueuedMessageResult::AlreadyStarted => {
            proto::RemoveQueuedUserMessageReason::AlreadyStarted
        }
        crate::engine::message::RemoveQueuedMessageResult::NotFound => {
            proto::RemoveQueuedUserMessageReason::NotFound
        }
    }
}

fn queue_target_to_proto(target: crate::engine::message::QueueTarget) -> proto::QueueTarget {
    proto::QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

fn log_seed_tool_drain_failed(session_id: Uuid, error: &anyhow::Error) {
    tracing::warn!(
        session_id = %session_id,
        error = %error,
        "seed-tool replay skipped because draining persisted seed tools failed"
    );
}

/// Resolve the root-frame agent for a session. Assistant sessions keep their
/// durable assistant identity so the shared agent loader can resolve the
/// authored assistant definition; ordinary sessions use their stored active
/// primary (so a resume restarts on whatever `Auto` handed off to, or a
/// `/plan` swap landed on), falling back to the configured default
/// ([`initial_active_agent`]) when unset/unknown. Shared by [`spawn`] (the
/// handle's initial chrome slot) and [`run_worker`] (the agent it actually
/// loads) so both agree.
pub(crate) fn resolve_root_agent(
    session_id: Uuid,
    db: &crate::db::Db,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    db.read_blocking(|conn| Ok(resolve_root_agent_conn(conn, session_id, cfg)))
        .unwrap_or_else(|_| initial_active_agent(cfg).to_string())
}

pub(crate) fn resolve_root_agent_conn(
    conn: &Connection,
    session_id: Uuid,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    let default_primary = || initial_active_agent(cfg).to_string();
    let Ok(Some(row)) = crate::db::Db::get_session_conn(conn, session_id) else {
        return default_primary();
    };
    if let Some(assistant_name) = row.assistant_name.as_deref() {
        if conn
            .query_row(
                "SELECT 1 FROM assistants WHERE name = ?1 LIMIT 1",
                rusqlite::params![assistant_name],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
        {
            return assistant_name.to_string();
        }
        return default_primary();
    }
    Some(row.active_agent)
        .filter(|name| {
            matches!(
                name.as_str(),
                "Auto" | "Plan" | "Build" | "Swarm" | "Multireview"
            )
        })
        // Experimental-mode gate (implementation note): a
        // session persisted on a now-gated primary (e.g. last on `Swarm`,
        // experimental since turned off) silently loads on `Build` instead —
        // no notice. With the flag on, the stored value is honored.
        .map(|name| crate::agents::resolve_primary_for_flag(&name, cfg.experimental_mode))
        .unwrap_or_else(default_primary)
}

/// Resolve the effective LLM mode for the session's active (provider, model)
/// against the override chain (implementation note): model
/// `mode` → provider `mode` → the persisted global `llm_mode` (`global`). When
/// no model is active or the providers config can't be loaded, the global
/// value passes through unchanged. Same first-hit config-layer rule as the
/// rest of the worker.
fn resolve_effective_llm_mode(
    session: &Session,
    providers: &crate::config::providers::ProvidersConfig,
    global: crate::config::extended::LlmMode,
) -> crate::config::extended::LlmMode {
    let (Some(provider), Some(model)) = (session.active_provider(), session.active_model()) else {
        return global;
    };
    providers.resolve_mode(&provider, &model, global)
}

/// Persist a live `/llm-mode` switch to the layered config so a resume
/// keeps it (implementation note). Writes to the
/// highest-precedence existing `config.json` on the discovered
/// path (the layer `load_for_cwd` would read), or — when none exists yet —
/// scaffolds one in the project `.cockpit/` so `/settings` + the config
/// file + `/llm-mode` all resolve to the same value. Round-trips through
/// [`ExtendedConfigDoc`] so unknown keys (including sibling layer/provider
/// metadata) survive.
fn persist_llm_mode(
    project_root: &std::path::Path,
    mode: crate::config::extended::LlmMode,
) -> anyhow::Result<()> {
    use crate::config::dirs::{CONFIG_FILE, discover_config_dirs};
    use crate::config::extended::ExtendedConfigDoc;
    let target = discover_config_dirs(project_root)
        .into_iter()
        .map(|d| d.path.join(CONFIG_FILE))
        .find(|p| p.exists())
        .unwrap_or_else(|| project_root.join(".cockpit").join(CONFIG_FILE));
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut cfg = doc.config();
    cfg.llm_mode = mode;
    doc.write(&cfg)?;
    Ok(())
}

/// Env var the daemon sets at boot when launched with `--no-sandbox`
/// (sandboxing part 2). Read per session-spawn to apply the
/// highest-precedence "OFF for ALL sessions" rule. Set internally only
/// (Layer B style); never a user-facing surface.
pub const DAEMON_NO_SANDBOX_ENV: &str = "COCKPIT_DAEMON_NO_SANDBOX";

/// Whether the running daemon was launched with `--no-sandbox`.
fn daemon_no_sandbox() -> bool {
    std::env::var_os(DAEMON_NO_SANDBOX_ENV).is_some()
}

/// Resolve the new-session sandbox default from the live daemon flag.
fn resolve_sandbox_default(
    client_no_sandbox: bool,
    configured_default: crate::tools::sandbox_mode::SandboxMode,
) -> crate::tools::sandbox_mode::SandboxMode {
    resolve_sandbox_default_with(daemon_no_sandbox(), client_no_sandbox, configured_default)
}

/// Pure precedence resolver (highest wins): daemon `--no-sandbox` ->
/// client `--no-sandbox` -> sandbox mode. Factored out from
/// [`resolve_sandbox_default`] so the precedence can be unit-tested without
/// touching process env.
fn resolve_sandbox_default_with(
    daemon_no_sandbox: bool,
    client_no_sandbox: bool,
    configured_default: crate::tools::sandbox_mode::SandboxMode,
) -> crate::tools::sandbox_mode::SandboxMode {
    if daemon_no_sandbox || client_no_sandbox {
        return crate::tools::sandbox_mode::SandboxMode::Off;
    }
    if configured_default.is_container() && !crate::container::availability_snapshot().available {
        crate::tools::sandbox_mode::SandboxMode::Sandbox
    } else {
        configured_default
    }
}

/// Resolve the per-session async-jobs concurrency cap (GOALS §22) from the
/// layered `config.json` rooted at `project_root`, falling back
/// to the default when none is configured.
fn max_concurrent_schedules_for(config: &crate::config::extended::ExtendedConfig) -> usize {
    config.schedule.max_concurrent
}

/// Resolve the loop-guard threshold (GOALS §1/§12) from the layered
/// `config.json` rooted at `project_root`, falling back to the
/// default (2 = fire on the first exact repeat) when none is configured.
fn loop_guard_threshold_for(config: &crate::config::extended::ExtendedConfig) -> u32 {
    config.loop_guard.effective_threshold()
}

fn max_primary_rounds_for(config: &crate::config::extended::ExtendedConfig) -> u32 {
    config.max_primary_rounds
}
