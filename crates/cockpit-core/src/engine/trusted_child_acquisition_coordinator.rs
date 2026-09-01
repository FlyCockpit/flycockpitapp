//! Trusted-child sealed-value acquisition coordinator.
//!
//! The host owns the destination and the only raw-output resolver. The child
//! receives a constrained binary-owned agent definition plus a task-local,
//! user-conferred capture capability. Successful command output is quarantined
//! at production time and can leave that quarantine only through an exact
//! single-use `source_tool_call_id` capture.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use crate::config::extended::{ApprovalMode, ExtendedConfig, SealedAcquisitionConsent};
use crate::config::providers::ProvidersConfig;
use crate::credentials::CredentialStore;
use crate::engine::builtin::SpawnArgs;
use crate::engine::driver::run_noninteractive_resumable;
use crate::engine::message::Message;
use crate::engine::model::Model;
use crate::engine::model_roles::resolve_trusted_child_model;
use crate::engine::trusted_child_acquisition::{AcquisitionOutcome, RequiresUser};
use crate::redact::RedactionTable;
use crate::session::Session;
use crate::session::trusted_child_capture::{
    SealedCaptureValue, TrustedChildCaptureOutcome, TrustedChildCaptureRegistry,
};
use crate::tools::trusted_child_acquisition::{
    AcquisitionRuntime, AcquisitionTerminalMove, with_acquisition_runtime,
};

const ACQUISITION_AGENT: &str = "sealed-acquisition";
const MAX_ACQUISITION_TURNS_PER_ATTEMPT: usize = 8;
const MAX_TERMINAL_NUDGES: usize = 2;
const TERMINAL_NUDGE: &str = "Choose exactly one terminal move now: capture_sealed_value(source_tool_call_id), acquisition_requires_user(reason, prompt), or acquisition_fail(). Never ask for or repeat the value.";

/// Owns the two lifecycle obligations that otherwise disappear when Tokio
/// drops a cancelled acquisition future. `Drop` is deliberately synchronous:
/// it first releases only its own in-memory reservation, then schedules the
/// idempotent durable terminal transition on the live runtime.
struct PendingAcquisitionGuard<'a> {
    registry: &'a TrustedChildCaptureRegistry,
    session_id: String,
    acquisition_id: String,
    db: crate::db::Db,
    armed: bool,
}

impl PendingAcquisitionGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingAcquisitionGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.registry.cancel(&self.session_id, &self.acquisition_id);
        let db = self.db.clone();
        let acquisition_id = self.acquisition_id.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = db
                    .finish_sealed_value_acquisition_audit(
                        acquisition_id,
                        "failed".to_owned(),
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await;
            });
        }
    }
}

/// Host-authored destination and model-selection request. No field is supplied
/// by the acquisition child, and the child brief must not name the destination.
pub struct AcquisitionRequest<'a> {
    pub caller_mode: ApprovalMode,
    pub category: &'a str,
    pub delegating_agent_name: &'a str,
    pub extended: &'a ExtendedConfig,
    pub providers: &'a ProvidersConfig,
    pub session_model: &'a Arc<Model>,
    pub store: Option<CredentialStore>,
    pub acquisition_id: &'a str,
    pub record_id: &'a str,
    pub value_name: &'a str,
    pub description: &'a str,
    pub generation: i64,
    /// Create-only sealed-value version. This is not a daemon protocol version.
    pub value_version: i64,
    pub now_ms: i64,
    /// Parent-supplied untrusted command. Destination metadata is a separate
    /// host-only concern and cannot be placed in the child brief by this API.
    pub command: String,
    /// Exact sealed references required to perform acquisition, usually empty.
    pub allowed_sealed_record_ids: BTreeSet<String>,
}

/// Runtime dependencies inherited from the parent session. Reusing the live
/// session and cwd makes sandbox posture identical; the task-local approval
/// projection independently maps auto to manual without mutating the parent.
pub struct AcquisitionExecutionContext {
    pub spawn_args: SpawnArgs,
    pub session: Arc<Session>,
    pub locks: Arc<crate::locks::LockManager>,
    pub redaction: Arc<RedactionTable>,
    pub config: crate::daemon::session_worker::SessionConfigHandle,
    pub guidance_compiler: Option<crate::computer::guidance::service::GuidanceCompiler>,
    pub interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    pub cancel: tokio_util::sync::CancellationToken,
    pub approver: Option<Arc<crate::approval::Approver>>,
    pub resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    pub local_installations: crate::agents::LocalInstallationResolver,
}

static PRODUCTION_CAPTURE_REGISTRY: OnceLock<TrustedChildCaptureRegistry> = OnceLock::new();

/// The sole production parent entry point. The dispatcher has the live parent
/// frame, so it can mint every child input and execution dependency itself;
/// the model supplies only the requested name, safe description, and command.
pub(crate) async fn run_parent_acquisition_tool(
    env: &crate::engine::agent::tool_dispatch::DispatchEnv<'_>,
    args: &serde_json::Value,
) -> anyhow::Result<crate::engine::tool::ToolOutput> {
    let name = args
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let description = args
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let command = args
        .get("command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let providers = env.ctx.config.providers();
    let extended = env.ctx.config.extended();
    let acquisition_id = uuid::Uuid::now_v7().to_string();
    let record_id = uuid::Uuid::now_v7().to_string();
    let spawn_args = SpawnArgs {
        compiled_guidance: Vec::new(),
        guidance_compiler: None,
        model: env.agent.model.clone(),
        params: env.agent.params.clone(),
        env_overlay: env.agent.env_overlay.clone(),
        cwd: env.ctx.cwd.clone(),
        config: env.ctx.config.clone(),
        session_short_id: env.ctx.session.short_id(),
        workspace_scratch_dir: env.ctx.session.workspace_scratch_dir(),
        assistant_identity_prefix: env.agent.assistant_identity_prefix.clone(),
        model_system_prompt_snapshot: env.ctx.session.model_system_prompt_snapshot(),
        knowledge_base_system_prefix: env.ctx.session.knowledge_base_system_prompt(),
        interactive: false,
        mcp_parent_reachable: Some(env.agent.mcp_resolver.catalog().admitted_entries()),
        mcp_root_catalog: env.agent.mcp_resolver.root_catalog(),
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        vnext_host_policy: None,
        vnext_local_installation_resolver:
            crate::agents::LocalInstallationResolver::no_installations(),
        parent_vnext_grant: None,
        parent_posture: None,
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: env.agent.write_scope.clone(),
        dream_read_scope: env.ctx.session.dream_read_scope(),
        workspace_lease: env.agent.workspace_lease.clone(),
        credential_store: env.ctx.session.provider_credential_store(&providers).ok(),
        media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
    };
    let outcome = run_trusted_child_acquisition(
        AcquisitionRequest {
            caller_mode: env.ctx.session.approval_mode(),
            category: "trusted-child-acquisition",
            delegating_agent_name: &env.agent.name,
            extended: &extended,
            providers: &providers,
            session_model: &env.agent.model,
            store: env.ctx.session.provider_credential_store(&providers).ok(),
            acquisition_id: &acquisition_id,
            record_id: &record_id,
            value_name: name,
            description,
            generation: i64::try_from(env.ctx.config.generation()).unwrap_or(i64::MAX),
            value_version: 1,
            now_ms: chrono::Utc::now().timestamp_millis(),
            command,
            allowed_sealed_record_ids: BTreeSet::new(),
        },
        AcquisitionExecutionContext {
            spawn_args,
            session: env.ctx.session.clone(),
            locks: env.ctx.locks.clone(),
            redaction: env.ctx.redact.clone(),
            config: env.ctx.config.clone(),
            guidance_compiler: None,
            interrupts: env.ctx.interrupts.clone(),
            cancel: env.ctx.cancel.clone(),
            approver: env.ctx.approver.clone(),
            resource_scheduler: env.ctx.resource_scheduler.clone(),
            local_installations: crate::agents::LocalInstallationResolver::no_installations(),
        },
        PRODUCTION_CAPTURE_REGISTRY.get_or_init(TrustedChildCaptureRegistry::new),
    )
    .await;
    Ok(crate::engine::tool::ToolOutput::text(match outcome {
        AcquisitionOutcome::Sealed => "sealed acquisition completed",
        AcquisitionOutcome::RequiresUser(_) => "sealed acquisition requires user input",
        AcquisitionOutcome::Failed => "sealed acquisition failed",
    }))
}

/// Perform one acquisition. The returned closed outcome is the only parent
/// result; no report, record id, source id, or literal is returned.
pub async fn run_trusted_child_acquisition(
    request: AcquisitionRequest<'_>,
    execution: AcquisitionExecutionContext,
    registry: &TrustedChildCaptureRegistry,
) -> AcquisitionOutcome {
    let started_at = Instant::now();
    let session_id = execution.session.id.to_string();

    if crate::sealed::identity::SealedRecordId::parse(request.record_id).is_err()
        || crate::sealed::identity::SealedName::canonical(request.value_name).is_err()
        || crate::sealed::identity::SealedDescription::parse(request.description).is_err()
        || request.acquisition_id.trim().is_empty()
        || request.command.trim().is_empty()
        || request.value_version != 1
    {
        return AcquisitionOutcome::Failed;
    }
    let Ok(true) = execution
        .session
        .db
        .agent_acquired_destination_available(
            session_id.clone(),
            request.record_id.to_owned(),
            request.value_name.to_owned(),
        )
        .await
    else {
        return AcquisitionOutcome::Failed;
    };

    // Audit-only is the default. The opt-in approval setting must have a live
    // owner approver and an affirmative one-shot decision before any child or
    // capture lifecycle exists.
    if request.extended.sealed_acquisition_consent == SealedAcquisitionConsent::Approval {
        let Some(approver) = execution.approver.as_ref() else {
            return AcquisitionOutcome::Failed;
        };
        // Consent is meaningful only when the owner can inspect the exact
        // command that will be run; never reduce this to a generic label.
        match approver
            .approve_tool_call(&format!(
                "trusted child credential acquisition command: {}",
                request.command
            ))
            .await
        {
            Ok(decision) if decision.is_allowed() => {}
            _ => return AcquisitionOutcome::Failed,
        }
    }

    let (child_model, _trusted_custody) = match resolve_trusted_child_model(
        request.category,
        request.delegating_agent_name,
        request.extended,
        request.providers,
        request.session_model,
        request.store,
    ) {
        Ok(selected) => selected,
        Err(_) => return AcquisitionOutcome::Failed,
    };

    let consent_mode = match request.extended.sealed_acquisition_consent {
        SealedAcquisitionConsent::AuditOnly => "audit_only",
        SealedAcquisitionConsent::Approval => "approval",
    };
    if execution
        .session
        .db
        .begin_sealed_value_acquisition_audit(
            crate::db::sealed_scope::NewSealedValueAcquisitionAudit {
                acquisition_id: request.acquisition_id.to_owned(),
                record_id: request.record_id.to_owned(),
                session_id: session_id.clone(),
                project_key: execution.session.project_id.clone(),
                name: request.value_name.to_owned(),
                description: request.description.to_owned(),
                child_agent: ACQUISITION_AGENT.to_owned(),
                consent_mode: consent_mode.to_owned(),
                created_at_ms: request.now_ms,
            },
        )
        .await
        .is_err()
    {
        return AcquisitionOutcome::Failed;
    }
    let mut pending_guard = PendingAcquisitionGuard {
        registry,
        session_id: session_id.clone(),
        acquisition_id: request.acquisition_id.to_owned(),
        db: execution.session.db.clone(),
        armed: true,
    };

    // Reserve before dispatch so concurrent acquisitions cannot both run a
    // secret-producing command. The source id is bound later because it does
    // not exist until the child emits the bash call.
    if registry
        .reserve_capture(
            &execution.session,
            request.acquisition_id,
            request.record_id,
            request.value_name,
            request.description,
            "trusted_child_acquisition",
            request.generation,
            request.value_version,
            request.now_ms,
        )
        .is_err()
    {
        terminalize_audit_failed(&execution.session, request.acquisition_id, request.now_ms).await;
        pending_guard.disarm();
        return AcquisitionOutcome::Failed;
    }

    let mut spawn_args = execution.spawn_args.clone();
    spawn_args.model = child_model;
    spawn_args.interactive = false;
    spawn_args.delegated = true;
    spawn_args.granted_tools.clear();
    // This owner action is not model-directed delegation. The ordinary
    // per-fork no-widening guard still applies through `parent_posture`; the
    // separate capture capability exists only in `AcquisitionRuntime` below.
    spawn_args.vnext_grant = None;
    spawn_args.parent_vnext_grant = None;
    spawn_args.vnext_host_policy = None;
    let child = match crate::engine::builtin::load(ACQUISITION_AGENT, &spawn_args) {
        Ok(child)
            if child.definition.as_ref().is_some_and(|definition| {
                definition.vnext.as_ref().is_some_and(|vnext| {
                    vnext
                        .capabilities
                        .contains(&crate::agents::AgentCapability::SealedAcquisitionCapture)
                })
            }) =>
        {
            child
        }
        _ => {
            terminalize_audit_failed(&execution.session, request.acquisition_id, request.now_ms)
                .await;
            registry.cancel(&session_id, request.acquisition_id);
            pending_guard.disarm();
            return AcquisitionOutcome::Failed;
        }
    };

    let runtime = AcquisitionRuntime::new(request.allowed_sealed_record_ids, request.caller_mode)
        .with_untrusted_command(request.command);
    let mut agent = child;
    let mut history = Vec::new();
    let mut prompt = Message::user(
        "Call run_acquisition_command exactly once under the normal sandbox and approval policy, then choose one terminal move. Do not repeat its output."
            .to_owned(),
    );
    let mut run_failed = false;
    for nudge in 0..=MAX_TERMINAL_NUDGES {
        let result = with_acquisition_runtime(
            runtime.clone(),
            run_noninteractive_resumable(
                agent,
                prompt,
                history,
                execution.session.clone(),
                execution.locks.clone(),
                execution.redaction.clone(),
                spawn_args.cwd.clone(),
                execution.config.clone(),
                execution.guidance_compiler.clone(),
                execution.interrupts.clone(),
                execution.cancel.clone(),
                execution.approver.clone(),
                execution.resource_scheduler.clone(),
                crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
                MAX_ACQUISITION_TURNS_PER_ATTEMPT,
                execution.local_installations.clone(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
            ),
        )
        .await;
        match result {
            Ok(outcome) => {
                history = outcome.history;
                agent = match crate::engine::builtin::load(ACQUISITION_AGENT, &spawn_args) {
                    Ok(agent) => agent,
                    Err(_) => {
                        run_failed = true;
                        break;
                    }
                };
            }
            Err(_) => {
                run_failed = true;
                break;
            }
        }
        if runtime.terminal().is_some() {
            break;
        }
        if nudge == MAX_TERMINAL_NUDGES {
            break;
        }
        prompt = Message::user(TERMINAL_NUDGE);
    }

    if run_failed {
        let completed_at_ms = completion_time_ms(request.now_ms, started_at);
        terminalize_audit_failed(&execution.session, request.acquisition_id, completed_at_ms).await;
        registry.cancel(&session_id, request.acquisition_id);
        pending_guard.disarm();
        return AcquisitionOutcome::Failed;
    }

    let completed_at_ms = completion_time_ms(request.now_ms, started_at);
    match runtime.terminal() {
        Some(AcquisitionTerminalMove::Capture {
            source_tool_call_id,
        }) => {
            let Some(authority) = registry.bind_source_tool_call(
                &session_id,
                request.acquisition_id,
                &source_tool_call_id,
                completed_at_ms,
            ) else {
                terminalize_audit_failed(
                    &execution.session,
                    request.acquisition_id,
                    completed_at_ms,
                )
                .await;
                registry.cancel(&session_id, request.acquisition_id);
                pending_guard.disarm();
                return AcquisitionOutcome::Failed;
            };
            let Some(mut quarantined) = runtime.take_quarantined(&source_tool_call_id) else {
                terminalize_audit_failed(
                    &execution.session,
                    request.acquisition_id,
                    completed_at_ms,
                )
                .await;
                registry.cancel(&session_id, request.acquisition_id);
                pending_guard.disarm();
                return AcquisitionOutcome::Failed;
            };
            let value = SealedCaptureValue::new(std::mem::take(&mut *quarantined));
            let outcome = match registry
                .verify_and_capture(
                    &execution.session,
                    &execution.redaction,
                    &authority.to_ingress(),
                    value,
                    completed_at_ms,
                )
                .await
            {
                TrustedChildCaptureOutcome::Captured { .. } => AcquisitionOutcome::Sealed,
                TrustedChildCaptureOutcome::Denied => {
                    terminalize_audit_failed(
                        &execution.session,
                        request.acquisition_id,
                        completed_at_ms,
                    )
                    .await;
                    registry.cancel(&session_id, request.acquisition_id);
                    AcquisitionOutcome::Failed
                }
            };
            pending_guard.disarm();
            outcome
        }
        Some(AcquisitionTerminalMove::RequiresUser { reason, prompt }) => {
            registry.cancel(&session_id, request.acquisition_id);
            let outcome = RequiresUser::parse(&reason, &prompt);
            let audit_outcome = if matches!(outcome, AcquisitionOutcome::RequiresUser(_)) {
                "requires_user"
            } else {
                "failed"
            };
            let _ = execution
                .session
                .db
                .finish_sealed_value_acquisition_audit(
                    request.acquisition_id.to_owned(),
                    audit_outcome.to_owned(),
                    completed_at_ms,
                )
                .await;
            pending_guard.disarm();
            outcome
        }
        Some(AcquisitionTerminalMove::Failed) | None => {
            terminalize_audit_failed(&execution.session, request.acquisition_id, completed_at_ms)
                .await;
            registry.cancel(&session_id, request.acquisition_id);
            pending_guard.disarm();
            AcquisitionOutcome::Failed
        }
    }
}

fn completion_time_ms(started_at_ms: i64, started_at: Instant) -> i64 {
    let elapsed_ms = i64::try_from(started_at.elapsed().as_millis()).unwrap_or(i64::MAX);
    started_at_ms.saturating_add(elapsed_ms)
}

async fn terminalize_audit_failed(session: &Session, acquisition_id: &str, now_ms: i64) {
    let _ = session
        .db
        .finish_sealed_value_acquisition_audit(
            acquisition_id.to_owned(),
            "failed".to_owned(),
            now_ms,
        )
        .await;
}

#[cfg(test)]
mod tests;
