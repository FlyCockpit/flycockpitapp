//! Trusted-child sealed-value acquisition coordinator.
//!
//! The host owns the destination and the only raw-output resolver. The child
//! receives a constrained binary-owned agent definition plus a task-local,
//! user-conferred capture capability. Successful command output is quarantined
//! at production time and can leave that quarantine only through an exact
//! single-use `source_tool_call_id` capture.

use std::collections::BTreeSet;
use std::sync::Arc;
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
        match approver
            .approve_tool_call("trusted child credential acquisition")
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
        registry.cancel(&session_id);
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
            registry.cancel(&session_id);
            return AcquisitionOutcome::Failed;
        }
    };

    let runtime = AcquisitionRuntime::new(request.allowed_sealed_record_ids, request.caller_mode);
    let mut agent = child;
    let mut history = Vec::new();
    let mut prompt = Message::user(format!(
        "Run this untrusted acquisition command under the normal sandbox and approval policy, then choose one terminal move. Do not repeat its output:\n{}",
        request.command
    ));
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
        registry.cancel(&session_id);
        return AcquisitionOutcome::Failed;
    }

    let completed_at_ms = completion_time_ms(request.now_ms, started_at);
    match runtime.terminal() {
        Some(AcquisitionTerminalMove::Capture {
            source_tool_call_id,
        }) => {
            let Some(authority) =
                registry.bind_source_tool_call(&session_id, &source_tool_call_id, completed_at_ms)
            else {
                terminalize_audit_failed(
                    &execution.session,
                    request.acquisition_id,
                    completed_at_ms,
                )
                .await;
                registry.cancel(&session_id);
                return AcquisitionOutcome::Failed;
            };
            let Some(mut quarantined) = runtime.take_quarantined(&source_tool_call_id) else {
                terminalize_audit_failed(
                    &execution.session,
                    request.acquisition_id,
                    completed_at_ms,
                )
                .await;
                registry.cancel(&session_id);
                return AcquisitionOutcome::Failed;
            };
            let value = SealedCaptureValue::new(std::mem::take(&mut *quarantined));
            match registry
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
                    registry.cancel(&session_id);
                    AcquisitionOutcome::Failed
                }
            }
        }
        Some(AcquisitionTerminalMove::RequiresUser { reason, prompt }) => {
            registry.cancel(&session_id);
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
            outcome
        }
        Some(AcquisitionTerminalMove::Failed) | None => {
            terminalize_audit_failed(&execution.session, request.acquisition_id, completed_at_ms)
                .await;
            registry.cancel(&session_id);
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
