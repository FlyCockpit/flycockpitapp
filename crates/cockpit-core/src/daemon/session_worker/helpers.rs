use super::*;

pub(super) async fn steer_delegation_side_channel(
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
    let rows = match session.db.list_task_delegation_children(session.id).await {
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
    match session
        .db
        .enqueue_task_delegation_steer(&row.task_call_id, &row.label, &message, &origin_principal)
        .await
    {
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

pub(super) fn queue_item_to_proto(
    item: crate::engine::message::QueuedUserMessage,
) -> proto::QueueItem {
    proto::QueueItem {
        id: item.id,
        status: match item.status {
            crate::engine::message::QueueItemStatus::Queued => proto::QueueItemStatus::Queued,
            crate::engine::message::QueueItemStatus::Folding => proto::QueueItemStatus::Folding,
        },
        text: item.text,
        display_text: item.display_text,
        target: queue_target_to_proto(item.target),
        delivery_class: item.delivery_class,
        send_now: item.send_now,
    }
}

pub(super) fn remove_reason_to_proto(
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
        crate::engine::message::RemoveQueuedMessageResult::EditConflict => {
            proto::RemoveQueuedUserMessageReason::EditConflict
        }
    }
}

pub(super) fn queue_target_to_proto(
    target: crate::engine::message::QueueTarget,
) -> proto::QueueTarget {
    proto::QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

/// Resolve the root-frame agent for a session. Assistant sessions keep their
/// durable assistant identity so the shared agent loader can resolve the
/// authored assistant definition; ordinary sessions use their stored active
/// primary (so a resume restarts on whatever `Auto` handed off to, or a
/// `/plan` swap landed on), falling back to the configured default
/// ([`initial_active_agent`]) when unset/unknown. Shared by [`spawn`] (the
/// handle's initial chrome slot) and [`run_worker`] (the agent it actually
/// loads) so both agree.
pub(crate) async fn resolve_root_agent(
    session_id: Uuid,
    db: &crate::db::Db,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    let fallback = initial_active_agent(cfg).to_string();
    let cfg = cfg.clone();
    db.read(move |conn| Ok(resolve_root_agent_conn(conn, session_id, &cfg)))
        .await
        .unwrap_or(fallback)
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
    if row.session_entry_mode == "computer" {
        return "Computer".to_string();
    }
    if row.assistant_name.as_deref() == Some(crate::assistants::PRIMARY_ASSISTANT_IDENTITY_NAME)
        && row.active_agent == "Assistant"
    {
        return "Assistant".to_string();
    }
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
    let active = row.active_agent;
    if crate::agents::is_builtin_primary(&active) {
        return crate::agents::resolve_primary(Some(&active), initial_active_agent(cfg));
    }
    if !active.trim().is_empty() {
        return active;
    }
    default_primary()
}

/// Environment override for the daemon sandbox default.
///
/// The daemon writes this to `1` when launched with `--no-sandbox`, and it is
/// also read from the daemon process environment at each session spawn. Its
/// value must be an explicit truthy value; malformed values fail closed with a
/// configuration error rather than silently disabling sandboxing.
pub const DAEMON_NO_SANDBOX_ENV: &str = "COCKPIT_DAEMON_NO_SANDBOX";

/// Whether the daemon environment explicitly disables sandboxing.
pub(crate) fn daemon_no_sandbox() -> anyhow::Result<bool> {
    let Some(value) = std::env::var_os(DAEMON_NO_SANDBOX_ENV) else {
        return Ok(false);
    };
    let value = value.to_string_lossy();
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!(
            "{DAEMON_NO_SANDBOX_ENV} must be one of 1, true, yes, on, 0, false, no, or off; got `{value}`"
        ),
    }
}

/// Persist sandbox intent (`sandbox.defaultMode`). Capability-missing
/// `SetSandbox` must not call this. Workspace-bound: the target is this
/// workspace's layer as [`crate::config::dirs::workspace_config_write_target`]
/// selects it under the session's own trust `policy` (the `COCKPIT_CONFIG`
/// override when set, else the nearest trusted project layer, else the
/// per-directory machine-local layer; a project `.cockpit/` is scaffolded
/// only under `Trust`). It never falls back to the user-global layer, and a
/// refusal is an error rather than a write somewhere else. The write itself
/// runs under the same policy, so the configuration document's own gate
/// judges the same decision.
pub(super) fn persist_sandbox_intent(
    project_root: &std::path::Path,
    policy: crate::config::trust::WorkspaceTrustPolicy,
    mode: crate::tools::sandbox_mode::SandboxIntent,
) -> anyhow::Result<()> {
    use crate::config::extended::ExtendedConfigDoc;
    crate::config::trust::with_workspace_trust_policy(policy, || {
        let target = crate::config::dirs::workspace_config_write_target(project_root)?;
        let mut doc = ExtendedConfigDoc::load(&target)?;
        let mut cfg = doc.config();
        // Persist unconditionally. A previous "skip if unchanged"
        // short-circuit compared against the ISOLATED target layer, which
        // could equal the requested mode while an outer layer still overrode
        // it, silently dropping a toggle-to-default. Writing the intent to
        // the nearest layer every time is idempotent and matches the other
        // session-preference persist helpers.
        cfg.sandbox.default_mode = mode;
        doc.write(&cfg)?;
        Ok(())
    })
}

/// Pure precedence resolver (highest wins): daemon `--no-sandbox` ->
/// client `--no-sandbox` -> [`super::effective_sandbox_mode`]. Factored out
/// from session spawn so the precedence can be unit-tested without touching
/// process env. Explicit `--no-sandbox` is Off. Unavailable sandbox or
/// container is Refuse, never silent Off or a rewrite to host Sandbox.
pub(super) fn resolve_sandbox_default_with(
    daemon_no_sandbox: bool,
    client_no_sandbox: bool,
    configured_default: crate::tools::sandbox_mode::SandboxIntent,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> crate::tools::sandbox_mode::SandboxMode {
    if daemon_no_sandbox || client_no_sandbox {
        return crate::tools::sandbox_mode::SandboxMode::Off;
    }
    super::apply_sandbox_intent(configured_default, caps)
}

/// Resolve the per-session async-jobs concurrency cap (GOALS §22) from the
/// layered `config.json` rooted at `project_root`, falling back
/// to the default when none is configured.
pub(super) fn max_concurrent_schedules_for(
    config: &crate::config::extended::ExtendedConfig,
) -> usize {
    config.schedule.max_concurrent
}

/// Resolve the loop-guard threshold (GOALS §1/§12) from the layered
/// `config.json` rooted at `project_root`, falling back to the
/// default (2 = fire on the first exact repeat) when none is configured.
pub(super) fn loop_guard_threshold_for(config: &crate::config::extended::ExtendedConfig) -> u32 {
    config.loop_guard.effective_threshold()
}

pub(super) fn max_primary_rounds_for(config: &crate::config::extended::ExtendedConfig) -> u32 {
    config.max_primary_rounds
}

#[cfg(test)]
mod persist_sandbox_intent_tests {
    use super::*;

    #[test]
    fn fresh_install_scaffolds_the_project_layer_not_the_global_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let global = crate::config::dirs::global_config_dir().unwrap();
        assert!(
            !global.is_dir(),
            "fresh-install fixture must not pre-create the global layer"
        );

        let trusted = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&project).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        persist_sandbox_intent(
            &project,
            trusted,
            crate::tools::sandbox_mode::SandboxIntent::Off,
        )
        .unwrap();

        let project_config = project
            .join(".cockpit")
            .join(crate::config::dirs::CONFIG_FILE);
        assert!(
            project_config.exists(),
            "per-project sandbox intent must scaffold project .cockpit: {}",
            project_config.display()
        );
        assert!(
            !global.join(crate::config::dirs::CONFIG_FILE).exists(),
            "per-project sandbox intent must not leak into the global layer"
        );
        let wire = std::fs::read_to_string(&project_config).unwrap();
        assert!(
            wire.contains("\"off\""),
            "scaffolded project config must persist the sandbox intent: {wire}"
        );
    }
}
