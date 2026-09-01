//! Canonical ordinary-tool dispatch pipeline.
//!
//! Every path that executes an ordinary tool call must go through
//! [`execute_ordinary_call`]. The live driver delegates here after name repair
//! and structural-tool routing; `interrupt-park-core` reuses the same unit for
//! persisted parked-call replay so an approved command runs through the exact
//! same safety, audit, event, redaction, and history contract.

use std::sync::Arc;

use anyhow::Context as _;

use super::*;

fn ordinary_ledger_args(env: &DispatchEnv<'_>, resolved_name: &str, args: &Value) -> Value {
    crate::tools::knowledge_sealed::ledger_args_for_sensitive_tool(resolved_name, args)
        .or_else(|| {
            env.active_tools
                .get(resolved_name)
                .map(|tool| tool.ledger_args(args))
        })
        .unwrap_or_else(|| args.clone())
}

/// The display/audit projection is intentionally distinct from this model-wire
/// projection. `x-cockpit-model-ephemeral` fields remain in the former, while
/// this value is the only argument shape persisted for replay.
fn model_history_args(env: &DispatchEnv<'_>, resolved_name: &str, args: &Value) -> Value {
    let display_args = ordinary_ledger_args(env, resolved_name, args);
    env.active_tools
        .get(resolved_name)
        .map(|tool| {
            crate::engine::tool::strip_model_ephemeral_fields(&display_args, &tool.parameters())
        })
        // MCP is intentionally unaffected: third-party schemas and their
        // unstructured results do not participate in this marker contract.
        .unwrap_or(display_args)
}

#[derive(Debug)]
pub(crate) struct SchedulerDurableOrder {
    next_started: std::sync::atomic::AtomicUsize,
    next_commit: std::sync::atomic::AtomicUsize,
    released_starts: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    released_commits: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    notify: tokio::sync::Notify,
}

impl SchedulerDurableOrder {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            next_started: std::sync::atomic::AtomicUsize::new(0),
            next_commit: std::sync::atomic::AtomicUsize::new(0),
            released_starts: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            released_commits: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            notify: tokio::sync::Notify::new(),
        })
    }

    fn release(
        &self,
        ordinal: usize,
        counter: &std::sync::atomic::AtomicUsize,
        released: &std::sync::Mutex<std::collections::BTreeSet<usize>>,
    ) {
        let mut released = released.lock().unwrap();
        released.insert(ordinal);
        let mut next = counter.load(std::sync::atomic::Ordering::Acquire);
        while released.remove(&next) {
            next += 1;
        }
        counter.store(next, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait_for(
        counter: &std::sync::atomic::AtomicUsize,
        ordinal: usize,
        notify: &tokio::sync::Notify,
    ) {
        loop {
            let notified = notify.notified();
            if counter.load(std::sync::atomic::Ordering::Acquire) == ordinal {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) struct SchedulerDurablePermit {
    order: Arc<SchedulerDurableOrder>,
    ordinal: usize,
    started_released: bool,
}

impl SchedulerDurablePermit {
    pub(crate) fn new(order: Arc<SchedulerDurableOrder>, ordinal: usize) -> Self {
        Self {
            order,
            ordinal,
            started_released: false,
        }
    }

    pub(crate) async fn await_started(&self) {
        SchedulerDurableOrder::wait_for(&self.order.next_started, self.ordinal, &self.order.notify)
            .await;
    }

    pub(crate) fn release_started(&mut self) {
        if !self.started_released {
            self.started_released = true;
            self.order.release(
                self.ordinal,
                &self.order.next_started,
                &self.order.released_starts,
            );
        }
    }

    pub(crate) async fn await_commit(&mut self) {
        SchedulerDurableOrder::wait_for(&self.order.next_commit, self.ordinal, &self.order.notify)
            .await;
    }
}

impl Drop for SchedulerDurablePermit {
    fn drop(&mut self) {
        self.release_started();
        // An error can leave before the common durable-commit boundary. Mark
        // that ordinal released as well so later completed calls never deadlock
        // behind a cancelled predecessor.
        self.order.release(
            self.ordinal,
            &self.order.next_commit,
            &self.order.released_commits,
        );
    }
}

tokio::task_local! {
    static SCHEDULER_DURABLE_PERMIT: Arc<tokio::sync::Mutex<SchedulerDurablePermit>>;
}

pub(crate) async fn with_scheduler_durable_order<F>(
    permit: SchedulerDurablePermit,
    future: F,
) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send + '_>> =
        Box::pin(future);
    SCHEDULER_DURABLE_PERMIT
        .scope(Arc::new(tokio::sync::Mutex::new(permit)), fut)
        .await
}

async fn scheduler_await_started() {
    if let Ok(permit) = SCHEDULER_DURABLE_PERMIT.try_with(Arc::clone) {
        permit.lock().await.await_started().await;
    }
}

async fn scheduler_release_started() {
    if let Ok(permit) = SCHEDULER_DURABLE_PERMIT.try_with(Arc::clone) {
        permit.lock().await.release_started();
    }
}

async fn scheduler_await_commit() {
    if let Ok(permit) = SCHEDULER_DURABLE_PERMIT.try_with(Arc::clone) {
        permit.lock().await.await_commit().await;
    }
}
use crate::db::needs_attention::{InterruptParkPayload, InterruptResumeAnchor};

pub(crate) struct DispatchEnv<'a> {
    pub(crate) agent: &'a Agent,
    pub(crate) session: &'a Arc<Session>,
    pub(crate) model: &'a Model,
    pub(crate) active_tools: &'a ToolBox,
    pub(crate) ctx: &'a ToolCtx,
    pub(crate) tx: &'a mpsc::Sender<TurnEvent>,
    pub(crate) hint_corrections: bool,
    pub(crate) loop_guard_threshold: u32,
    pub(crate) cwd: &'a std::path::Path,
    /// Turn-pinned hook registry. Resolved once from the config snapshot and
    /// immutable for the turn. A config reload affects later turns only; no
    /// hook set changes between `preToolUse` and its matching post event.
    pub(crate) hooks: &'a crate::config::extended::hooks::HookRegistry,
}

struct ResolvedToolMediaHandoff {
    mapping: crate::typed_media_result::ProviderRigMapping,
    lease: Option<crate::media_storage::VerifiedHeldMedia>,
}

async fn resolve_tool_media_handoffs(
    env: &DispatchEnv<'_>,
    tc: &ToolCall,
    output: &ToolOutput,
) -> Result<Vec<ResolvedToolMediaHandoff>> {
    use anyhow::Context as _;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let references = output
        .content
        .parts()
        .iter()
        .filter_map(|part| part.as_media_reference())
        .collect::<Vec<_>>();
    if references.is_empty() {
        return Ok(Vec::new());
    }
    let (storage, _) = env
        .session
        .message_media_authority()
        .context("media_reference_unavailable: durable media authority is not installed")?;
    let project_text = env
        .session
        .project_root
        .to_str()
        .context("media_reference_unavailable: project root is not UTF-8")?;
    let auth = crate::typed_media_result::MediaReferenceAuthContext {
        session_id: env.session.id,
        canonical_project_digest: crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes())),
    };
    let providers = env.ctx.config.providers();
    let capabilities = providers.resolve_effective_model_capabilities(
        env.model.provider_id(),
        env.model.model_id_ref(),
        providers.resolution_generation,
    );
    let profile = crate::typed_media_result::ModelCapabilityProfile {
        image_in_tool_result: env.model.is_anthropic_native_wire()
            && capabilities.supports_image_input(),
        image_in_user_content: !env.model.is_anthropic_native_wire()
            && capabilities.supports_image_input(),
        audio_in_user_content: capabilities.supports_audio_input(),
        video_in_user_content: capabilities.supports_video_input(),
    };
    let resolver = crate::typed_media_result::MediaReferenceResolver::new(&auth, &profile);
    let call_id = tc
        .provider
        .as_ref()
        .map(|provider| provider.call_id.as_str());
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut handoffs: Vec<ResolvedToolMediaHandoff> = Vec::with_capacity(references.len());
    for reference in references {
        if !matches!(
            reference.purpose,
            crate::typed_media_result::MediaReferencePurpose::Primary
        ) {
            for handoff in handoffs {
                if let Some(lease) = handoff.lease {
                    let _ = lease.release(now_ms).await;
                }
            }
            anyhow::bail!(
                "media_reference_unavailable: only primary tool-result media has a provider handoff"
            );
        }
        let resolved = storage
            .resolve_tool_media_reference(
                &resolver,
                &auth,
                reference,
                crate::typed_media_result::MediaRoute::Primary,
                &tc.id.to_string(),
                call_id,
                now_ms,
            )
            .await;
        let (resolved, lease) = match resolved {
            Ok(value) => value,
            Err(error) => {
                for handoff in handoffs {
                    if let Some(lease) = handoff.lease {
                        let _ = lease.release(now_ms).await;
                    }
                }
                return Err(anyhow::anyhow!("media_reference_unavailable: {error}"));
            }
        };
        let Some(bytes) = resolved.bytes.as_ref() else {
            if let Some(lease) = lease {
                let _ = lease.release(now_ms).await;
            }
            for handoff in handoffs {
                if let Some(lease) = handoff.lease {
                    let _ = lease.release(now_ms).await;
                }
            }
            anyhow::bail!("media_reference_unavailable: primary mapping has no bytes");
        };
        let base64_bytes = base64::engine::general_purpose::STANDARD.encode(&bytes.bytes);
        let mapping =
            crate::typed_media_result::map_to_provider_rig(&resolved, reference, &base64_bytes)
                .map_err(|error| anyhow::anyhow!("media_reference_unavailable: {error}"));
        let mapping = match mapping {
            Ok(mapping) => mapping,
            Err(error) => {
                if let Some(lease) = lease {
                    let _ = lease.release(now_ms).await;
                }
                for handoff in handoffs {
                    if let Some(lease) = handoff.lease {
                        let _ = lease.release(now_ms).await;
                    }
                }
                return Err(error);
            }
        };
        handoffs.push(ResolvedToolMediaHandoff { mapping, lease });
    }
    Ok(handoffs)
}

async fn release_tool_media_handoffs(handoffs: &mut Option<Result<Vec<ResolvedToolMediaHandoff>>>) {
    let Some(Ok(handoffs)) = handoffs.take() else {
        return;
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    for handoff in handoffs {
        if let Some(lease) = handoff.lease {
            let _ = lease.release(now_ms).await;
        }
    }
}

enum RepeatCallAuthorization {
    Run,
    RecoverableRefusal(String),
    ConfirmationDenied { consecutive: u32 },
}

/// Verification outcomes after the automatic-projection escalation has been
/// resolved through the user approval boundary. Keeping this separate from
/// `VerificationOutcome` makes it impossible for the host-effect dispatch
/// match below to accidentally bypass an unresolved escalation.
enum DispatchVerificationOutcome {
    Skip,
    DispatchOriginal {
        plan: crate::engine::verification::intercept::VerificationDispatchPlan,
    },
    Block {
        message: String,
        operation_id: Option<uuid::Uuid>,
    },
    Revise {
        args: serde_json::Value,
        disclosure: String,
        plan: crate::engine::verification::intercept::VerificationDispatchPlan,
    },
}

fn verification_host_settlement(
    hard_fail: bool,
    host_effect_unknown: bool,
    has_projection_event: bool,
) -> crate::db::verification_ledger::DispatchSettlement {
    match (has_projection_event, hard_fail, host_effect_unknown) {
        (true, true, _) => crate::db::verification_ledger::DispatchSettlement::Failed,
        (true, false, true) => crate::db::verification_ledger::DispatchSettlement::Unknown,
        (true, false, false) => crate::db::verification_ledger::DispatchSettlement::Succeeded,
        (false, _, _) => crate::db::verification_ledger::DispatchSettlement::Unknown,
    }
}

/// A replayed verification memo owns a live dispatch reservation only for a
/// selected revision or a durably selected original.  Both must be settled if
/// replay is refused before entering the host-effect boundary.
fn replay_memo_has_reserved_dispatch(
    memo: &crate::db::needs_attention::InterruptVerificationMemo,
) -> bool {
    memo.dispatch_attempt_revision >= 0
        && matches!(
            memo.outcome,
            crate::db::needs_attention::InterruptVerificationOutcome::Revise { .. }
                | crate::db::needs_attention::InterruptVerificationOutcome::DispatchOriginal
        )
}

async fn cancel_replayed_reserved_dispatch(
    session: &Session,
    memo: Option<&crate::db::needs_attention::InterruptVerificationMemo>,
) -> Result<()> {
    let Some(memo) = memo.filter(|memo| replay_memo_has_reserved_dispatch(memo)) else {
        return Ok(());
    };
    cancel_verification_dispatch_no_submission(
        session,
        memo.operation_id,
        memo.dispatch_attempt_revision,
        b"verification-selected-replay-authorization-refused",
    )
    .await
}

/// Cancellation occurs before the host-effect boundary, so a failure to
/// terminalize its durable reservation must fail the live call closed. In
/// particular, do not report a normal refusal or denial while a CAS or
/// database failure could have left the dispatch attempt unresolved.
async fn cancel_verification_dispatch_no_submission(
    session: &Session,
    operation_id: uuid::Uuid,
    attempt_revision: i64,
    proof: &'static [u8],
) -> Result<()> {
    session
        .db
        .cancel_verification_dispatch_no_submission(
            session.id,
            operation_id,
            attempt_revision,
            crate::db::verification_ledger::NoSubmissionProof::from_digest(
                crate::db::verification_ledger::VerificationDigest::of(proof),
            ),
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        .with_context(|| {
            format!(
                "verification dispatch {operation_id} could not be terminalized safely; recovery must reconcile the reservation"
            )
        })?;
    Ok(())
}

/// Apply the argument-dependent repeat authorities to one canonical call.
/// Revised calls use this same seam after substitution, while parked replays
/// naturally run it once through the ordinary pipeline with their memoized
/// selected arguments.
async fn authorize_repeat_call(
    env: &DispatchEnv<'_>,
    resolved_name: &str,
    args: &Value,
    eligible: bool,
) -> Result<RepeatCallAuthorization> {
    if !eligible {
        env.session.clear_recoverable_tool_call();
        return Ok(RepeatCallAuthorization::Run);
    }
    let signature = crate::approval::store::GrantStore::loop_signature(resolved_name, args);
    if let Some(message) = env
        .session
        .repeated_recoverable_tool_call_message(&signature)
    {
        return Ok(RepeatCallAuthorization::RecoverableRefusal(message));
    }
    let Some(approver) = env.ctx.approver.as_ref() else {
        return Ok(RepeatCallAuthorization::Run);
    };
    let consecutive = env.session.bump_consecutive_call(&signature);
    if consecutive < env.loop_guard_threshold.max(1) {
        return Ok(RepeatCallAuthorization::Run);
    }
    let interactive = env.ctx.interrupts.is_interactive_attached();
    if approver
        .approve_repeat(resolved_name, args, interactive)
        .await?
        .is_accept()
    {
        Ok(RepeatCallAuthorization::Run)
    } else {
        Ok(RepeatCallAuthorization::ConfirmationDenied { consecutive })
    }
}

enum BtwNativeAuthorization {
    Run,
    Refused {
        message: String,
        permission_kind: &'static str,
    },
}

/// `/btw` is a separate native-tool approval authority. It must see the exact
/// arguments headed to the host, including verification-selected arguments.
async fn authorize_btw_native_call(
    env: &DispatchEnv<'_>,
    resolved_name: &str,
    args: &Value,
) -> Result<BtwNativeAuthorization> {
    let Some(tool) = env.active_tools.get(resolved_name) else {
        return Ok(BtwNativeAuthorization::Run);
    };
    if !env.session.is_btw_fork() || !crate::engine::tool::tool_requires_permission(tool.as_ref()) {
        return Ok(BtwNativeAuthorization::Run);
    }
    let label = format!("`{resolved_name}` in /btw side conversation");
    let decision = if let Some(approver) = env.ctx.approver.as_ref() {
        approver
            .authorize(crate::approval::AuthorizationRequest::NativeTool {
                label: &label,
                input: args,
            })
            .await?
    } else {
        crate::approval::Decision::NoninteractiveDeny
    };
    Ok(match decision {
        crate::approval::Decision::Allow { .. } => BtwNativeAuthorization::Run,
        crate::approval::Decision::NoninteractiveDeny => BtwNativeAuthorization::Refused {
            message: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
            permission_kind: "approval_noninteractive_denied",
        },
        crate::approval::Decision::Deny => BtwNativeAuthorization::Refused {
            message: "btw side conversation: mutating tool call denied".to_string(),
            permission_kind: "approval_denied",
        },
        crate::approval::Decision::StandingReject { scope } => BtwNativeAuthorization::Refused {
            message: crate::approval::standing_reject_refusal(resolved_name, scope),
            permission_kind: "blocked_standing_reject",
        },
    })
}

enum RevisedCallAuthorization {
    Ready { args: Value, recheck_result: bool },
    Refused(String),
}

/// Re-enter every pre-host boundary whose decision depended on substituted
/// arguments. Verification itself is deliberately not called from here: the
/// selected candidate already has a memoized durable decision, while schema
/// repair/path normalization, the safety gate, and pre-tool hooks must all see
/// the exact call that will reach the tool.
async fn authorize_revised_call(
    env: &DispatchEnv<'_>,
    resolved_name: &str,
    call_id: &str,
    schema: &Value,
    proposed_args: Value,
    payload: &mut InterruptParkPayload,
) -> Result<RevisedCallAuthorization> {
    let mut canonical =
        crate::engine::model::wire_schema::strip_wire_nulls(schema, proposed_args.clone());
    let repaired = repair(&mut canonical, schema, resolved_name);
    if !repaired.valid {
        return Ok(RevisedCallAuthorization::Refused(format!(
            "verification selected invalid replacement arguments: {}",
            repaired
                .error
                .unwrap_or_else(|| "schema validation failed".into())
        )));
    }
    let normalized = repair::normalize_paths(&mut canonical, schema, env.cwd);
    if let Some(error) = normalized.error {
        return Ok(RevisedCallAuthorization::Refused(format!(
            "verification selected invalid replacement arguments: {error}"
        )));
    }
    // Collection canonicalizes before adjudication. A mismatch here means the
    // selected bytes and reserved envelope disagree, so do not silently apply
    // a different call under the selected candidate's digest.
    if canonical != proposed_args {
        return Ok(RevisedCallAuthorization::Refused(
            "verification selected replacement arguments that changed during final normalization; revise and re-emit"
                .into(),
        ));
    }
    if let Err(error) =
        guard_redaction_placeholder_tool_args(resolved_name, &canonical, env.ctx).await
    {
        return Ok(RevisedCallAuthorization::Refused(error.to_string()));
    }

    let replay_gate_memo = crate::engine::interrupt::current_interrupt_park_payload()
        .filter(|parked| {
            parked.tool == resolved_name && parked.call_id == call_id && parked.args == canonical
        })
        .and_then(|parked| parked.gate);
    payload.args = canonical.clone();
    payload.gate = replay_gate_memo;
    match authorize_repeat_call(env, resolved_name, &canonical, true).await? {
        RepeatCallAuthorization::Run => {}
        RepeatCallAuthorization::RecoverableRefusal(message) => {
            return Ok(RevisedCallAuthorization::Refused(message));
        }
        RepeatCallAuthorization::ConfirmationDenied { consecutive } => {
            return Ok(RevisedCallAuthorization::Refused(loop_guard_message(
                resolved_name,
                &canonical,
                consecutive,
                &env.active_tools.names(),
            )));
        }
    }
    let mut recheck_result = false;
    if super::is_gated_tool(resolved_name) {
        match crate::engine::interrupt::with_interrupt_park_payload(
            payload.clone(),
            safety_gate_decision(resolved_name, &canonical, env.ctx, env.tx),
        )
        .await
        {
            GateOutcome::Run { recheck } => {
                recheck_result = recheck;
                payload.gate = Some(crate::db::needs_attention::InterruptGateMemo {
                    recheck_result: recheck,
                });
            }
            GateOutcome::Parked => return Err(crate::engine::interrupt::InterruptParked.into()),
            GateOutcome::Block(block) => {
                return Ok(RevisedCallAuthorization::Refused(block.message));
            }
        }
    }

    if let BtwNativeAuthorization::Refused {
        message,
        permission_kind,
    } = authorize_btw_native_call(env, resolved_name, &canonical).await?
    {
        fire_permission_denied_hook(env, resolved_name, call_id, permission_kind).await;
        return Ok(RevisedCallAuthorization::Refused(message));
    }

    let pre_hook = super::hooks::run_pre_tool_hooks(
        &super::hooks::TokioCommandRunner::with_optional_containment(
            env.session.process_containment(),
        ),
        &super::hooks::DefaultProcessEnv,
        env.hooks,
        resolved_name,
        &canonical,
        call_id,
        env.session.id,
        env.cwd,
        &env.session.db,
        crate::knowledge::local_knowledge_write_fence_active(
            env.session,
            env.cwd,
            &env.ctx.config.extended(),
        )
        .await,
    )
    .await;
    if let super::hooks::PreHookOutcome::Deny { reason } = pre_hook {
        return Ok(RevisedCallAuthorization::Refused(reason));
    }
    Ok(RevisedCallAuthorization::Ready {
        args: canonical,
        recheck_result,
    })
}
/// The authorization portion of ordinary dispatch, reused by Monty's builtin
/// adapter. Monty is a transport, not a second tool-execution authority: a
/// host invocation must consume the same safety gate, standing rejects,
/// review cage, and repeat budget as a model-issued native call.
pub(crate) async fn authorize_monty_native_call(
    tool: &dyn crate::engine::tool::Tool,
    args: &Value,
    ctx: &crate::engine::tool::ToolCtx,
) -> Result<MontyNativeAuthorization> {
    let fallback_events;
    let tx = if let Some(events) = ctx.events.as_ref() {
        events
    } else {
        let (events, _receiver) = mpsc::channel(8);
        fallback_events = events;
        &fallback_events
    };

    match safety_gate_decision(tool.name(), args, ctx, tx).await {
        GateOutcome::Run { .. } => {}
        GateOutcome::Parked => return Err(crate::engine::interrupt::InterruptParked.into()),
        GateOutcome::Block(block) => {
            fire_monty_permission_denied_hook(ctx, tool.name(), "authorization_blocked").await;
            return Ok(MontyNativeAuthorization::Denied(serde_json::json!({
                "denied": true,
                "kind": "authorization_blocked",
                "tool": tool.name(),
                "message": block.message,
            })));
        }
    }

    if let Some(cage) = ctx.review_cage.as_ref()
        && let Err(error) = cage.allow_dispatch(tool.name())
    {
        fire_monty_permission_denied_hook(ctx, tool.name(), "review_cage_denied").await;
        return Ok(MontyNativeAuthorization::Denied(serde_json::json!({
            "denied": true,
            "kind": "review_cage_denied",
            "tool": tool.name(),
            "message": error.to_string(),
        })));
    }

    if let Some(approver) = ctx.approver.as_ref() {
        let signature = crate::approval::store::GrantStore::loop_signature(tool.name(), args);
        let consecutive = ctx.session.bump_consecutive_call(&signature);
        let threshold = ctx.config.extended().loop_guard.effective_threshold();
        if consecutive >= threshold {
            let interactive = ctx.interrupts.is_interactive_attached();
            if !approver
                .approve_repeat(tool.name(), args, interactive)
                .await?
                .is_accept()
            {
                let available: Vec<&str> = ctx.available_tools.iter().map(String::as_str).collect();
                fire_monty_permission_denied_hook(ctx, tool.name(), "loop_guard_denied").await;
                return Ok(MontyNativeAuthorization::Denied(serde_json::json!({
                    "denied": true,
                    "kind": "loop_guard_denied",
                    "tool": tool.name(),
                    "message": loop_guard_message(tool.name(), args, consecutive, &available),
                })));
            }
        }
    }

    if !crate::engine::tool::tool_requires_permission(tool) {
        return Ok(MontyNativeAuthorization::Allowed);
    }

    let label = format!("`{}` via cockpit MCP {}", tool.name(), args);
    let decision = if let Some(approver) = ctx.approver.as_ref() {
        approver
            .authorize(crate::approval::AuthorizationRequest::NativeTool {
                label: &label,
                input: args,
            })
            .await?
    } else {
        crate::approval::Decision::NoninteractiveDeny
    };
    let denied = match decision {
        crate::approval::Decision::Allow { .. } => return Ok(MontyNativeAuthorization::Allowed),
        crate::approval::Decision::Deny => {
            ("approval_denied", "native tool call denied".to_string())
        }
        crate::approval::Decision::StandingReject { scope } => (
            "approval_denied",
            crate::approval::standing_reject_refusal(tool.name(), scope),
        ),
        crate::approval::Decision::NoninteractiveDeny => (
            "approval_noninteractive_denied",
            crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
        ),
    };
    fire_monty_permission_denied_hook(ctx, tool.name(), denied.0).await;
    Ok(MontyNativeAuthorization::Denied(serde_json::json!({
        "denied": true,
        "kind": denied.0,
        "tool": tool.name(),
        "message": denied.1,
    })))
}

pub(crate) enum MontyNativeAuthorization {
    Allowed,
    Denied(Value),
}

/// Fire `permissionDenied` observe hooks for a real denial of a Monty-issued
/// native tool call. Monty is a transport, not a second authorization authority,
/// so a host-issued call that the shared safety gate / review cage / loop guard /
/// approval driver denies must produce the same `permissionDenied` observability
/// as a model-issued native call — otherwise a matcher configured against that
/// event would silently miss every Monty denial.
///
/// Observe-only and fail-open: a hook failure never alters the deny decision.
/// `permissionKind` is the exact deny `kind` string the Monty denial payload
/// already carries, so the hook reports what the host receives. Unlike the
/// ordinary path there is no turn-pinned registry to reuse here (a host call is
/// not part of a model turn's pinned hook set), so the registry is resolved from
/// the current config snapshot — matching `Driver::fire_observe_hook`.
async fn fire_monty_permission_denied_hook(
    ctx: &crate::engine::tool::ToolCtx,
    tool_name: &str,
    permission_kind: &'static str,
) {
    let snapshot = ctx.config.snapshot();
    let extended = snapshot.extended.clone();
    let local_knowledge_write_fence_active =
        crate::knowledge::local_knowledge_write_fence_active(&ctx.session, &ctx.cwd, &extended)
            .await;
    super::hooks::run_observe_hooks(
        &super::hooks::TokioCommandRunner::with_optional_containment(
            ctx.session.process_containment(),
        ),
        &super::hooks::DefaultProcessEnv,
        snapshot.hooks(),
        crate::config::extended::hooks::HookEvent::PermissionDenied,
        tool_name,
        ctx.session.id,
        &ctx.cwd,
        &ctx.session.db,
        Some(tool_name),
        ctx.current_tool_call_id.as_deref(),
        None,
        None,
        super::hooks::ObserveFields {
            permission_kind: Some(permission_kind),
            ..Default::default()
        },
        local_knowledge_write_fence_active,
    )
    .await;
}

/// Fire `permissionDenied` observe hooks for a real approval / safety-gate /
/// review-cage / standing-reject denial of an ordinary tool. Observe-only and
/// fail-open: a hook failure never alters the deny decision. Matcher = resolved
/// canonical tool name; `permissionKind` = the existing deny status string the
/// deny site already carries. Not fired for a pre-tool hook deny or a
/// schema-repair failure.
async fn fire_permission_denied_hook(
    env: &DispatchEnv<'_>,
    tool_name: &str,
    tool_call_id: &str,
    permission_kind: &'static str,
) {
    let extended = env.ctx.config.extended();
    let local_knowledge_write_fence_active =
        crate::knowledge::local_knowledge_write_fence_active(env.session, env.cwd, &extended).await;
    super::hooks::run_observe_hooks(
        &super::hooks::TokioCommandRunner::with_optional_containment(
            env.session.process_containment(),
        ),
        &super::hooks::DefaultProcessEnv,
        env.hooks,
        crate::config::extended::hooks::HookEvent::PermissionDenied,
        tool_name,
        env.session.id,
        env.cwd,
        &env.session.db,
        Some(tool_name),
        Some(tool_call_id),
        None,
        None,
        super::hooks::ObserveFields {
            permission_kind: Some(permission_kind),
            ..Default::default()
        },
        local_knowledge_write_fence_active,
    )
    .await;
}

pub(crate) async fn execute_ordinary_call(
    env: &DispatchEnv<'_>,
    history: &mut Vec<Message>,
    tc: &ToolCall,
    resolved_name: &str,
    name_recovery: Recovery,
    text_recovery_marker: Option<Recovery>,
) -> Result<()> {
    // Approval gates run before `dispatch_one_timed`, while the concrete tool
    // call gets its own nested boundary inside the timeout wrapper. The outer
    // scope owns approvals raised by loop/safety/btw gates and receives the
    // actual `ToolOutput` outcome below; the inner scope owns approvals raised
    // from within the tool itself. Without this enclosing scope a gate could
    // consume a host approval before any effect boundary existed to own it.
    crate::engine::interrupt::with_host_approval_effect_scope(
        "ordinary_tool_dispatch_gate",
        env.ctx.cancel.clone(),
        Box::pin(execute_ordinary_call_unscoped(
            env,
            history,
            tc,
            resolved_name,
            name_recovery,
            text_recovery_marker,
        )),
        |_| None,
    )
    .await
}

async fn execute_ordinary_call_unscoped(
    env: &DispatchEnv<'_>,
    history: &mut Vec<Message>,
    tc: &ToolCall,
    resolved_name: &str,
    name_recovery: Recovery,
    text_recovery_marker: Option<Recovery>,
) -> Result<()> {
    let mut args = tc.function.arguments.clone();
    // §14 wire-vs-user split for a text-recovered call: the user-facing
    // `original_input` is the model's exact text block (carried on the
    // recovery marker), not the lifted args — so the timeline shows the
    // text the model actually emitted with the recovery chip, while the
    // wire/model form is the structured call. For an ordinary structured
    // call `original` stays the args as before.
    let original = match &text_recovery_marker {
        Some(Recovery::TextEmbedded { original, .. }) => Value::String(original.clone()),
        _ => args.clone(),
    };
    let placeholder_block = guard_redaction_placeholder_tool_args(resolved_name, &args, env.ctx)
        .await
        .err();
    let placeholder_blocked = placeholder_block.is_some();

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
    let schema = env
        .active_tools
        .advertised_tool(resolved_name)
        .map(|t| t.parameters())
        .unwrap_or(Value::Null);
    args = crate::engine::model::wire_schema::strip_wire_nulls(&schema, args);
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
        let model_id = env.model.model_id_ref();
        let provider_id = env.model.provider_id();
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
    // tool_result only when `env.hint_corrections` is enabled
    // (implementation note); the user transcript is
    // never altered. Empty on a clean/unrecoverable call.
    let repair_hints: Vec<String> = if env.hint_corrections {
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
        let norm = repair::normalize_paths(&mut args, &schema, env.cwd);
        if let Some(err) = norm.error {
            repair_outcome.valid = false;
            path_not_found = norm.not_found;
            // Steer mid-turn: a nonexistent path is best recovered by
            // listing what actually exists. Point at `code {kind:"tree"}` when the agent
            // holds it (every file-capable primary/subagent does); fall
            // back to the generic repair-layer diagnostic otherwise.
            repair_outcome.error = Some(if path_not_found && env.ctx.has_tree {
                format!(
                    "Error: `{}` does not exist; run `code` with kind `tree` to see existing files before reading.",
                    args.get("path").and_then(Value::as_str).unwrap_or_default()
                )
            } else {
                err
            });
        } else if matches!(recovery, Recovery::Clean) {
            recovery = norm.recovery;
        }
    }

    // A parked revised dispatch resumes at the ordinary-call entry point, but
    // its durable verification memo is already authoritative for which args
    // may reach the host. Substitute those args before repeat, safety, /btw,
    // cage, and pre-hook authorization so replay never authorizes the stale
    // original call and then skips authorization of the selected revision.
    let replay_verification_memo = crate::engine::interrupt::current_interrupt_park_payload()
        .filter(|parked| parked.tool == resolved_name && parked.call_id == tc.id.as_str())
        .and_then(|parked| parked.verification);
    if let Some(crate::db::needs_attention::InterruptVerificationOutcome::Revise {
        args: selected_args,
        ..
    }) = replay_verification_memo.as_ref().map(|memo| &memo.outcome)
    {
        args = selected_args.clone();
    }

    // Liveness refresh (`read-wait-and-lock-expiry.md`): every tool
    // call by this `(session, agent)` pushes back the idle-expiry
    // deadline of the locks it holds, so an agent legitimately mid-task
    // never loses a lock to the sweeper. One central refresh here, not
    // per-tool — it covers every dispatched call uniformly.
    env.ctx
        .locks
        .touch_holder(&env.ctx.agent_id, env.ctx.session.id)
        .await;

    let _ = env
        .tx
        .send(TurnEvent::ToolStart {
            agent: env.agent.name.clone(),
            call_id: tc.id.to_string(),
            tool: resolved_name.to_string(),
            args: ordinary_ledger_args(env, resolved_name, &args),
        })
        .await;

    // The provider was told an advertised-but-unavailable tool exists, so its
    // call must produce that availability result directly. In particular, do
    // not let a stale repeated-call signature turn an unavailable capability
    // into an approval prompt or loop-guard refusal.
    let unavailable_call = env.active_tools.unavailable_call_message(resolved_name);

    // Loop guard (GOALS §1/§12): block a back-to-back identical tool
    // call (same name + canonical post-repair `wire_input`) pending
    // approval. Only schema-valid calls are guarded — a malformed call
    // already short-circuits below, and isn't a "loop" worth
    // prompting on. The chain is maintained on `session` so it spans
    // turns; an intervening different call resets the count. When the
    // guard rejects (one-off, an always-reject rule, or headless), the
    // call is *not* dispatched and a guidance error stands in as the
    // tool result so the model changes course. With no approver wired
    // (tool tests/headless) the guard is skipped — never
    // silently denied, matching the command/path approval contract.
    // `loop_guard_reject` gates dispatch; `loop_guard_count` is the live
    // consecutive-repeat count of the rejected `(tool, args)` run, carried
    // to the wire-history collapse site (`loop-collapse-structural-
    // dedup.md`) so the synthesized message can state "called N times".
    let mut loop_guard_count: u32 = 0;
    let repeat_authorization = authorize_repeat_call(
        env,
        resolved_name,
        &args,
        repair_outcome.valid && !placeholder_blocked && unavailable_call.is_none(),
    )
    .await?;
    let repeated_recoverable_tool_call = match &repeat_authorization {
        RepeatCallAuthorization::RecoverableRefusal(message) => Some(message.clone()),
        _ => None,
    };
    let loop_guard_reject = match repeat_authorization {
        RepeatCallAuthorization::ConfirmationDenied { consecutive } => {
            loop_guard_count = consecutive;
            true
        }
        RepeatCallAuthorization::Run | RepeatCallAuthorization::RecoverableRefusal(_) => false,
    };

    // Command-safety gate (implementation note):
    // in `auto` approval mode each gated call (`bash`/`mcp`)
    // is judged by the utility model — with NO history —
    // before it runs. `safe` → run; `unsafe` (or utility model
    // unavailable → fail CLOSED) → escalate to the user; a denial skips
    // dispatch. The verdict also says whether the result needs a
    // post-run injection re-check (handled after dispatch). Only
    // evaluated for schema-valid, non-loop-rejected gated calls.
    let replay_gate_memo = crate::engine::interrupt::current_interrupt_park_payload()
        .filter(|payload| {
            payload.tool == resolved_name
                && payload.args == args
                && payload.call_id == tc.id.as_str()
        })
        .and_then(|payload| payload.gate);
    let base_park_payload = InterruptParkPayload {
        tool: resolved_name.to_string(),
        args: args.clone(),
        call_id: tc.id.to_string(),
        resume: InterruptResumeAnchor {
            agent_id: env.agent.name.clone(),
            call_id: tc.id.to_string(),
            provider_item_id: tc
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.clone()),
            provider_call_id: tc
                .provider
                .as_ref()
                .map(|provider| provider.call_id.clone()),
            assistant_seq: None,
            call_origin: env.ctx.skill_write_origin,
        },
        gate: replay_gate_memo,
        verification: None,
    };
    let mut recheck_result = false;
    let mut gate_memo = replay_gate_memo;
    let mut gate_block_status = "blocked_safety_gate";
    let gate_block: Option<String> = if unavailable_call.is_none()
        && !placeholder_blocked
        && repair_outcome.valid
        && !loop_guard_reject
        && super::is_gated_tool(resolved_name)
    {
        let gate_future = crate::engine::interrupt::with_interrupt_park_payload(
            base_park_payload.clone(),
            safety_gate_decision(resolved_name, &args, env.ctx, env.tx),
        );
        match Box::pin(gate_future).await {
            GateOutcome::Run { recheck } => {
                recheck_result = recheck;
                gate_memo = Some(crate::db::needs_attention::InterruptGateMemo {
                    recheck_result: recheck,
                });
                None
            }
            GateOutcome::Parked => {
                return Err(crate::engine::interrupt::InterruptParked.into());
            }
            GateOutcome::Block(block) => {
                gate_block_status = block.status;
                Some(block.message)
            }
        }
    } else {
        None
    };
    let guard = crate::config::extended::resolve_injection_guard(env.cwd);
    if should_scan_tool_result(
        resolved_name,
        env.agent.scan_tool_results,
        env.session.approval_mode(),
        guard.threshold,
    ) {
        recheck_result = true;
    }
    let cage_block: Option<String> =
        if unavailable_call.is_none() && !placeholder_blocked && repair_outcome.valid {
            env.ctx
                .review_cage
                .as_ref()
                .and_then(|cage| cage.allow_dispatch(resolved_name).err())
                .map(|err| err.to_string())
        } else {
            None
        };

    // Dispatch only when validate-then-repair produced a schema-valid
    // call AND the loop guard didn't reject it AND the safety gate didn't
    // block it AND any background-review cage allowed it. Otherwise skip
    // dispatch and treat the
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
    // (`not_in_advertised_set`) — structural tools (`task`/`done`/
    // `schedule`/`spawn`/`return`) already returned above, so any unknown name
    // here is a hallucination.
    // Loop-guard / safety-gate blocks are NOT rejections in this sense (the
    // call was valid and advertised) and are not classified.
    // Generic-dispatch refusal of a provider identifier reserved for the
    // native computer-use tool (`computer-coordinator-live-loop-and-dispatch-
    // wiring.md` §4). A provider may surface a native `computer_call` /
    // `computer_20251124` / `computer_20250124` item to the generic Rig
    // `AssistantContent::ToolCall` layer; ordinary function-tool dispatch must
    // never execute it as an ordinary tool nor re-parse native computer JSON
    // here (those items are executed only through the coordinator's raw-content
    // extraction seam). This is a tool-call NAME/TYPE guard — it is orthogonal
    // to the `computer` subagent, which is built only via `task` delegation
    // (`engine::builtin::load`) and never reaches this ordinary path. The name
    // is not in the advertised toolbox, so absent this guard it would already
    // fall to `not_in_advertised_set` below; the explicit, reserved-specific
    // refusal makes the intent auditable and cannot be defeated by a future
    // toolbox change that registers the name.
    let reserved_native_computer =
        crate::computer::is_reserved_native_computer_tool_name(resolved_name);
    let rejection_reason: Option<&'static str> = if reserved_native_computer {
        Some("reserved_native_computer_tool")
    } else if placeholder_blocked
        || loop_guard_reject
        || gate_block.is_some()
        || cage_block.is_some()
    {
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
    } else if env.active_tools.call_availability(resolved_name)
        == crate::engine::tool::ToolCallAvailability::NotAdvertised
    {
        Some("not_in_advertised_set")
    } else {
        None
    };
    // Every syntactically valid provider call owns a durable lifecycle, even
    // when it is rejected because the current tool surface does not advertise
    // it.  In a scheduled mixed lane that rejected call is still a serial
    // barrier, so omitting its `started` row makes the audit sequence diverge
    // from the provider's source order.  `tool_rejected` remains the separate
    // classification for the unavailable call; it is not a reason to erase
    // the lifecycle attempt.
    let lifecycle_started = placeholder_blocked || repair_outcome.valid;
    // Pin the AUTHORING model's frame inputs ONCE — its `(provider, model)`, the
    // config handle, and the pre-policy session table (captured as one Arc) — at
    // the authoring point, and reuse them for EVERY model-authored event AND the
    // co-persisted audit row below. This is the single source of truth for this
    // dispatch's journal-vs-scrub classification, so the audit row and its
    // ToolCall event (and the started/rejected/completed events) can never be
    // classified against different frames across the execution/persistence awaits
    // (TOCTOU; mirrors the MCP recorder's construction-time pin and schedule's
    // one-frame pass). `env.model` is `&Model`, immutable for this call.
    let tool_provider = env.model.provider_id().to_string();
    let tool_model = env.model.model_id_ref().to_string();
    let tool_session_table = env.model.session_redact_table();
    let tool_frame = || crate::session::SessionEventModelFrame {
        provider_id: &tool_provider,
        model_id: &tool_model,
        config: &env.ctx.config,
        session_table: tool_session_table.as_ref(),
    };
    // Parallel calls may finish in any order, but their durable lifecycle
    // starts and completed audit/event bundles are committed in original
    // source order. Actual read-only tool execution remains concurrent between
    // these two short ordering gates.
    scheduler_await_started().await;
    let mut assistant_seq = None;
    if lifecycle_started {
        let (start_recovery_kind, start_recovery_stage) = recovery.db_fields();
        let ledger_original = ordinary_ledger_args(env, resolved_name, &original);
        let ledger_wire = model_history_args(env, resolved_name, &args);
        let start_data = serde_json::json!({
            "tool": resolved_name,
            "original_input": ledger_original,
            "wire_input": ledger_wire,
            "recovery_kind": start_recovery_kind,
            "recovery_stage": start_recovery_stage,
        });
        match env
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::ToolCallStarted,
                Some(&env.agent.name),
                Some(&tc.id),
                tool_frame(),
                &start_data,
            )
            .await
        {
            Ok(seq) => {
                assistant_seq = Some(seq);
            }
            Err(e) => {
                tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_started event failed");
            }
        }
    }
    scheduler_release_started().await;
    let gate_blocked = gate_block.is_some();
    let repeated_recoverable_tool_call_reject = repeated_recoverable_tool_call.is_some();
    // `permissionDenied` observe-hook classification (Decision 3): a real
    // approval / safety-gate / standing-reject / review-cage denial of an
    // ordinary tool. NOT fired for a schema-repair failure, a placeholder
    // block, a recoverable-repeat guidance message, or the pre-tool hook deny
    // (which returns before reaching the deny-audit site below). `permissionKind`
    // is the existing deny status string this path already produces (`gate.rs`
    // block status for the gate, the tool-call-completed lifecycle status for
    // the loop guard, and the canonical `review_cage_denied` kind for the cage).
    let mut permission_denied_kind: Option<&'static str> =
        // A reserved native-computer name is a structural refusal, never a
        // permission denial — even when the same call would ALSO trip the loop
        // guard or review cage (its reserved-refusal arm wins the `result`
        // below). Classify it as `None` so no `permissionDenied` observe hook
        // fires under it.
        if reserved_native_computer
            || placeholder_blocked
            || !repair_outcome.valid
            || repeated_recoverable_tool_call_reject
        {
            None
        } else if loop_guard_reject {
            Some("blocked_loop_guard")
        } else if gate_blocked {
            Some(gate_block_status)
        } else if cage_block.is_some() {
            Some("review_cage_denied")
        } else {
            None
        };
    // Track whether a real tool execution actually occurred. Existing
    // gate/sandbox/approval refusals, schema-validation failures, loop-guard
    // rejections, and placeholder blocks are NOT executions and fire no post
    // hook. Only the `dispatch_one_timed` path is a real execution.
    let mut tool_was_dispatched = false;
    let mut verification_disclosure: Option<String> = None;
    let mut verification_blocked = false;
    let mut verification_dispatch_plan: Option<
        crate::engine::verification::intercept::VerificationDispatchPlan,
    > = None;
    let selected_replay_denied_before_intercept = reserved_native_computer
        || placeholder_blocked
        || repeated_recoverable_tool_call_reject
        || loop_guard_reject
        || gate_blocked
        || cage_block.is_some()
        || unavailable_call.is_some()
        || !repair_outcome.valid;
    if selected_replay_denied_before_intercept {
        cancel_replayed_reserved_dispatch(env.session, replay_verification_memo.as_ref()).await?;
    }
    let (result, duration_ms) = if reserved_native_computer {
        // Refuse with zero backend input — never call `dispatch_one_timed`.
        // The model reads back a deterministic diagnostic; the native computer
        // path is the only route that executes these items.
        (
            Err(invalid_input(format!(
                "`{resolved_name}` is reserved for the provider-native computer-use tool and \
                 cannot be executed as an ordinary function tool; native computer actions are \
                 dispatched only through the native computer path, not generic tool calls"
            ))),
            0,
        )
    } else if let Some(err) = placeholder_block {
        (Err(err), 0)
    } else if let Some(msg) = repeated_recoverable_tool_call.clone() {
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
                &env.active_tools.names(),
            ))),
            0,
        )
    } else if let Some(msg) = gate_block {
        (Err(invalid_input(msg)), 0)
    } else if let Some(msg) = cage_block {
        (Err(invalid_input(msg)), 0)
    } else if let Some(message) = unavailable_call {
        // The provider was told this tool exists, so a call is not a
        // hallucination. Return a normal call-time availability result without
        // entering approvals, hooks, verification, or the tool body.
        (Err(anyhow::anyhow!(message)), 0)
    } else if repair_outcome.valid {
        if let BtwNativeAuthorization::Refused {
            message,
            permission_kind,
        } = authorize_btw_native_call(env, resolved_name, &args).await?
        {
            cancel_replayed_reserved_dispatch(env.session, replay_verification_memo.as_ref())
                .await?;
            // A /btw approval denial early-returns before the common deny-audit
            // site below, so `permissionDenied` must fire here (observe-only /
            // fail-open) with the matching deny kind — otherwise a real
            // approval / standing-reject denial of a mutating ordinary tool in a
            // side conversation would fire no hook.
            fire_permission_denied_hook(env, resolved_name, &tc.id, permission_kind).await;
            return Err(invalid_input(message));
        }
        let mut payload = InterruptParkPayload {
            tool: resolved_name.to_string(),
            args: args.clone(),
            call_id: tc.id.to_string(),
            resume: InterruptResumeAnchor {
                agent_id: env.agent.name.clone(),
                call_id: tc.id.to_string(),
                provider_item_id: tc
                    .provider
                    .as_ref()
                    .and_then(|provider| provider.item_id.clone()),
                provider_call_id: tc
                    .provider
                    .as_ref()
                    .map(|provider| provider.call_id.clone()),
                assistant_seq,
                call_origin: env.ctx.skill_write_origin,
            },
            gate: gate_memo,
            verification: None,
        };
        // Pre-tool hook gate: runs after name/argument/path repair and after
        // existing loop/safety/review/btw decisions permit dispatch, but
        // before `dispatch_one_timed`. A hook can deny only by printing valid
        // JSON `{"decision":"deny","reason":"..."}` to stdout. The first
        // explicit deny short-circuits later pre hooks and the tool is not
        // executed. Pre-hook failures are fail-open.
        let pre_hook_decision = super::hooks::run_pre_tool_hooks(
            &super::hooks::TokioCommandRunner::with_optional_containment(
                env.session.process_containment(),
            ),
            &super::hooks::DefaultProcessEnv,
            env.hooks,
            resolved_name,
            &args,
            &tc.id,
            env.session.id,
            env.cwd,
            &env.session.db,
            crate::knowledge::local_knowledge_write_fence_active(
                env.session,
                env.cwd,
                &env.ctx.config.extended(),
            )
            .await,
        )
        .await;
        if let super::hooks::PreHookOutcome::Deny { reason } = &pre_hook_decision {
            cancel_replayed_reserved_dispatch(env.session, replay_verification_memo.as_ref())
                .await?;
            // The deny is already recorded by `run_pre_tool_hooks` via
            // `record_hook_run`. Return the deterministic model-visible
            // rejected-tool diagnostic; the tool is never executed and no
            // post hook fires.
            return Err(invalid_input(reason.clone()));
        }
        // ArtifactWrite verification: after every human/host approval (safety
        // gate, loop, cage, /btw, pre-tool hooks) and before `dispatch_one_timed`.
        // Frame inputs are already pinned above. A matching rule completes its
        // durable collection/adjudication decision before any host effect.
        // The compiled grant is also scoped so sibling Monty native write/edit
        // can resolve the same policy without a second Agent handle.
        crate::engine::verification::with_current_vnext_grant(
            env.agent.vnext_grant.clone(),
            async {
        let verification = crate::engine::verification::intercept_ordinary_call(
            crate::engine::verification::InterceptInput {
                session: env.session,
                agent: env.agent,
                model: env.model,
                ctx: env.ctx,
                history,
                resolved_name,
                args: &args,
                call_id: tc.id.as_str(),
            },
        )
        .await;
        let verification = match verification {
            crate::engine::verification::VerificationOutcome::Escalate { plan } => {
                // A trusted-minimal projection failure must never degrade to
                // a model-visible refusal that the user cannot act on. Keep
                // the already-reserved original call in the park payload so
                // a user-approved replay consumes this durable decision
                // rather than collecting/adjudicating a second operation.
                let operation_id = plan.operation_id;
                payload.verification = Some(
                    crate::db::needs_attention::InterruptVerificationMemo {
                        operation_id,
                        dispatch_attempt_revision: plan.attempt_revision,
                        outcome: crate::db::needs_attention::InterruptVerificationOutcome::DispatchOriginal,
                    },
                );
                let label = format!(
                    "verification could not safely project this `{resolved_name}` call for automatic approval; approve it manually"
                );
                let decision = match env.ctx.approver.as_ref() {
                    Some(approver) => crate::engine::interrupt::with_interrupt_park_payload(
                        payload.clone(),
                        approver.authorize(crate::approval::AuthorizationRequest::NativeTool {
                            label: &label,
                            input: &args,
                        }),
                    )
                    .await,
                    None => Ok(crate::approval::Decision::NoninteractiveDeny),
                };
                match decision {
                    Ok(crate::approval::Decision::Allow { .. }) => {
                        DispatchVerificationOutcome::DispatchOriginal { plan }
                    }
                    Err(error) if crate::engine::interrupt::is_parked(&error) => {
                        return (Err(crate::engine::interrupt::InterruptParked.into()), 0);
                    }
                    Ok(_) | Err(_) => {
                        if let Err(error) = cancel_verification_dispatch_no_submission(
                            env.session,
                            operation_id,
                            plan.attempt_revision,
                            b"verification-projection-escalation-declined",
                        )
                        .await
                        {
                            return (Err(error), 0);
                        }
                        verification_blocked = true;
                        // This is a real user-approval boundary, unlike an
                        // ordinary verification block. Preserve its observer
                        // audit after the rejected tool result is durable.
                        permission_denied_kind = Some("blocked_verification");
                        DispatchVerificationOutcome::Block {
                            message: "verification could not safely project this action for automatic approval and the user declined to run it manually; revise and re-emit".into(),
                            operation_id: Some(operation_id),
                        }
                    }
                }
            }
            crate::engine::verification::VerificationOutcome::Skip => {
                DispatchVerificationOutcome::Skip
            }
            crate::engine::verification::VerificationOutcome::DispatchOriginal { plan } => {
                DispatchVerificationOutcome::DispatchOriginal { plan }
            }
            crate::engine::verification::VerificationOutcome::Block {
                message,
                operation_id,
            } => DispatchVerificationOutcome::Block {
                message,
                operation_id,
            },
            crate::engine::verification::VerificationOutcome::Revise {
                args,
                disclosure,
                plan,
            } => DispatchVerificationOutcome::Revise {
                args,
                disclosure,
                plan,
            },
        };
        match verification {
            DispatchVerificationOutcome::Block {
                message,
                operation_id,
            } => {
                verification_blocked = true;
                if let Some(operation_id) = operation_id {
                    payload.verification =
                        Some(crate::db::needs_attention::InterruptVerificationMemo {
                            operation_id,
                            dispatch_attempt_revision: -1,
                            outcome:
                                crate::db::needs_attention::InterruptVerificationOutcome::Block {
                                    message: message.clone(),
                                },
                        });
                }
                (Err(invalid_input(message)), 0)
            }
            DispatchVerificationOutcome::Revise {
                args: revised_args,
                disclosure,
                mut plan,
            } => {
                let operation_id = plan.operation_id;
                let replaying_selected_args = crate::engine::interrupt::current_interrupt_park_payload()
                    .is_some_and(|parked| {
                        parked.tool == resolved_name
                            && parked.call_id == tc.id.as_str()
                            && parked.args == revised_args
                            && parked.verification.as_ref().is_some_and(|memo| {
                                memo.operation_id == operation_id
                                    && matches!(
                                        &memo.outcome,
                                        crate::db::needs_attention::InterruptVerificationOutcome::Revise { args, .. }
                                            if args == &revised_args
                                    )
                            })
                    });
                payload.verification =
                    Some(crate::db::needs_attention::InterruptVerificationMemo {
                        operation_id,
                        dispatch_attempt_revision: plan.attempt_revision,
                        outcome: crate::db::needs_attention::InterruptVerificationOutcome::Revise {
                            args: revised_args.clone(),
                            disclosure: disclosure.clone(),
                        },
                    });
                let authorization = if replaying_selected_args {
                    // Replay has already entered this ordinary pipeline with
                    // the selected args, so its validation, repeat and /btw
                    // approvals, safety gate, and pre-tool hooks ran above
                    // before the memo was consumed.
                    RevisedCallAuthorization::Ready {
                        args: revised_args.clone(),
                        recheck_result: false,
                    }
                } else {
                    match authorize_revised_call(
                        env,
                        resolved_name,
                        tc.id.as_str(),
                        &schema,
                        revised_args.clone(),
                        &mut payload,
                    )
                    .await
                    {
                        Ok(authorization) => authorization,
                        Err(error) => return (Err(error), 0),
                    }
                };
                match authorization {
                    RevisedCallAuthorization::Refused(message) => {
                        if let Err(error) = cancel_verification_dispatch_no_submission(
                            env.session,
                            operation_id,
                            plan.attempt_revision,
                            b"verification-revised-call-authorization-refused",
                        )
                        .await
                        {
                            return (Err(error), 0);
                        }
                        verification_blocked = true;
                        (Err(invalid_input(message)), 0)
                    }
                    RevisedCallAuthorization::Ready {
                        args: authorized_args,
                        recheck_result: revised_recheck,
                    } => {
                        recheck_result |= revised_recheck;
                        match env
                            .session
                            .db
                            .mark_verification_dispatch_executing(
                                env.session.id,
                                operation_id,
                                plan.attempt_revision,
                                chrono::Utc::now().timestamp_millis(),
                            )
                            .await
                        {
                            Ok(attempt) => plan.attempt_revision = attempt.revision,
                            Err(error) => {
                                verification_blocked = true;
                                tracing::warn!(%error, %operation_id, "verification dispatch reservation could not enter executing");
                                return (
                                    Err(invalid_input(
                                        "verification dispatch could not be reserved safely; revise and re-emit",
                                    )),
                                    0,
                                );
                            }
                        }
                        payload.verification = payload.verification.map(|mut memo| {
                            memo.dispatch_attempt_revision = plan.attempt_revision;
                            memo
                        });
                        if !super::rewrite_assistant_tool_call(
                            history,
                            tc.id.as_str(),
                            &authorized_args,
                        ) {
                            if let Err(error) = cancel_verification_dispatch_no_submission(
                                env.session,
                                operation_id,
                                plan.attempt_revision,
                                b"verification-provider-signature-rewrite-refused",
                            )
                            .await
                            {
                                return (Err(error), 0);
                            }
                            verification_blocked = true;
                            let message = "verification produced a revision, but this provider-signed assistant turn cannot be rewritten safely; revise and re-emit"
                                .to_string();
                            payload.verification =
                                Some(crate::db::needs_attention::InterruptVerificationMemo {
                                    operation_id,
                                    dispatch_attempt_revision: -1,
                                    outcome: crate::db::needs_attention::InterruptVerificationOutcome::Block {
                                        message: message.clone(),
                                    },
                                });
                            (Err(invalid_input(message)), 0)
                        } else {
                            args = authorized_args;
                            payload.args = args.clone();
                            tool_was_dispatched = true;
                            let dispatched = crate::engine::interrupt::with_interrupt_park_payload(
                                payload,
                                async {
                                    dispatch_one_timed(
                                        env.active_tools,
                                        resolved_name,
                                        args.clone(),
                                        env.ctx,
                                        Some(&tc.id),
                                    )
                                    .await
                                },
                            )
                            .await;
                            verification_disclosure = Some(disclosure);
                            verification_dispatch_plan = Some(plan);
                            dispatched
                        }
                    }
                }
            }
            DispatchVerificationOutcome::Skip => {
                tool_was_dispatched = true;
                crate::engine::interrupt::with_interrupt_park_payload(payload, async {
                    dispatch_one_timed(
                        env.active_tools,
                        resolved_name,
                        args.clone(),
                        env.ctx,
                        Some(&tc.id),
                    )
                    .await
                })
                .await
            }
            DispatchVerificationOutcome::DispatchOriginal { mut plan } => {
                let operation_id = plan.operation_id;
                let attempt = match env
                    .session
                    .db
                    .mark_verification_dispatch_executing(
                        env.session.id,
                        operation_id,
                        plan.attempt_revision,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await
                {
                    Ok(attempt) => attempt,
                    Err(error) => {
                        tracing::warn!(%error, %operation_id, "verification original dispatch reservation could not enter executing");
                        return (
                            Err(invalid_input(
                                "verification dispatch could not be reserved safely; revise and re-emit",
                            )),
                            0,
                        );
                    }
                };
                plan.attempt_revision = attempt.revision;
                payload.verification = Some(
                    crate::db::needs_attention::InterruptVerificationMemo {
                        operation_id,
                        dispatch_attempt_revision: plan.attempt_revision,
                        outcome: crate::db::needs_attention::InterruptVerificationOutcome::DispatchOriginal,
                    },
                );
                tool_was_dispatched = true;
                let dispatched =
                    crate::engine::interrupt::with_interrupt_park_payload(payload, async {
                        dispatch_one_timed(
                            env.active_tools,
                            resolved_name,
                            args.clone(),
                            env.ctx,
                            Some(&tc.id),
                        )
                        .await
                    })
                    .await;
                verification_dispatch_plan = Some(plan);
                dispatched
            }
        }
            },
        )
        .await
    } else {
        let msg = repair_outcome
            .error
            .unwrap_or_else(|| format!("`{resolved_name}` arguments failed schema validation"));
        (Err(invalid_input(msg)), 0)
    };
    // This is the outer approval scope's exact effect outcome. The nested
    // timeout scope has already completed any approval raised *inside* the
    // tool; this records the result for approvals raised by the loop/safety/
    // btw gates before that tool boundary existed. A pre-dispatch refusal is
    // definitively rejected. An execution error deliberately remains unset so
    // the outer scope records submission-unknown rather than guessing whether
    // an external command/MCP call crossed its boundary before failing.
    match &result {
        Ok(output) if tool_was_dispatched => {
            crate::engine::interrupt::record_host_approval_effect_boundary_outcome(
                output.exit_code.is_none_or(|code| code == 0),
            );
        }
        Err(_) if !tool_was_dispatched => {
            crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
        }
        Ok(_) | Err(_) => {}
    }
    if result
        .as_ref()
        .is_err_and(crate::engine::interrupt::is_parked)
    {
        let Err(err) = result else {
            unreachable!("checked error branch above");
        };
        return Err(err);
    }

    // Defensive bash-routing nudge self-suppression
    // (implementation note): a SUCCESSFUL
    // call to a dedicated file/search tool (`read`/`search`/`code`) marks that
    // tip as adopted for the session, so a
    // later `bash` file/search command stops appending the corresponding
    // tip. Recorded once here at the single dispatch chokepoint; the `bash`
    // result-assembly site reads it. Non-tip tools record nothing.
    if result.is_ok() && crate::tools::shell_compress::tip_adopted_by(resolved_name).is_some() {
        env.session.record_tip_tool_used(resolved_name);
    }

    // Post-tool hooks: run once after a successful real tool execution
    // (`postToolUse`) or after a real tool execution that returns an error
    // (`postToolUseFailure`). Existing gate/sandbox/approval refusals are not
    // executions and fire no post hook. Rejected/parked calls produce no post
    // event (the pre-hook deny and park paths already returned above; schema
    // failures and gate rejections set `tool_was_dispatched = false`).
    if tool_was_dispatched {
        let post_event = if result.is_ok() {
            crate::config::extended::hooks::HookEvent::PostToolUse
        } else {
            crate::config::extended::hooks::HookEvent::PostToolUseFailure
        };
        super::hooks::run_post_tool_hooks(
            &super::hooks::TokioCommandRunner::with_optional_containment(
                env.session.process_containment(),
            ),
            &super::hooks::DefaultProcessEnv,
            env.hooks,
            post_event,
            resolved_name,
            &args,
            &tc.id,
            &result,
            env.session.id,
            env.cwd,
            &env.session.db,
            crate::knowledge::local_knowledge_write_fence_active(
                env.session,
                env.cwd,
                &env.ctx.config.extended(),
            )
            .await,
        )
        .await;
    }

    // Canonical-form history rewrite. Two layers can feed the model's
    // own corrected call back into `history` so its next inference sees
    // the shape that would have matched at stage 1:
    //
    //   - §13c tool recovery: a tool returns a recovery + canonical args
    //     (today only `edit`); this is authoritative because it
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
    // Keep the complete result metadata in the durable/display projection.
    // The schema marker produces the model projection at this one storage
    // boundary; today's built-in metadata fields are all marked, so this is
    // empty without a dispatcher-maintained exclusion list.
    let mut result_metadata = match &result {
        Ok(out) => out.result_metadata(),
        Err(_) => serde_json::Map::new(),
    };
    // Canonical result contents and ToolOutput audit metadata are distinct JSON
    // namespaces. Keep the native schema as its own projection root so local
    // references such as `#/$defs/result` resolve against the schema that
    // declared them; metadata uses ToolOutput's fixed marker schema instead.
    let model_result_contents_schema = env
        .active_tools
        .get(resolved_name)
        .map(|tool| tool.result_schema());
    let model_result_metadata = crate::engine::tool::strip_model_ephemeral_fields(
        &Value::Object(result_metadata.clone()),
        &ToolOutput::result_metadata_schema(),
    );
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
        let fix_command = crate::tools::shell_sandbox::fix_command_for_reason(&remedy);
        let _ = env
            .tx
            .send(TurnEvent::SandboxUnavailable {
                remedy,
                fix_command,
            })
            .await;
    }
    // §13c tool recovery additionally rebinds `args` so the audit row's
    // `wire_input_json` is the tool's canonical form; the shape-repair
    // fallback needs no rebind (`args` is already the repaired form).
    if wire_args.is_some() {
        args = wire_args.clone().unwrap();
    }
    let history_args =
        history_rewrite_args(wire_args.as_ref(), &args, repair_outcome.valid, &recovery)
            .unwrap_or(&args);
    // Store-time projection must also rewrite the live assistant call.
    // Otherwise a marked value would survive in the just-built history until
    // restart even though the durable replay row correctly omits it.
    let model_wire_args = model_history_args(env, resolved_name, history_args);
    rewrite_assistant_tool_call(history, &tc.id, &model_wire_args);
    if let Some(signature) = repair_outcome
        .valid
        .then(|| crate::approval::store::GrantStore::loop_signature(resolved_name, &args))
    {
        if let Some(RepeatGuard { message }) = repeat_guard.clone() {
            env.session
                .remember_recoverable_tool_call(signature, message);
        } else if let Some(message) = repeated_recoverable_tool_call.clone() {
            env.session
                .remember_recoverable_tool_call(signature, message);
        } else {
            env.session.clear_recoverable_tool_call();
        }
    } else {
        env.session.clear_recoverable_tool_call();
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

    let mut resolved_media_handoffs = match &result {
        Ok(output) => Some(resolve_tool_media_handoffs(env, tc, output).await),
        Err(_) => None,
    };
    let model_result_contents = result
        .as_ref()
        .ok()
        .map(|output| {
            model_result_contents_schema
                .as_ref()
                .map(|schema| output.content.strip_model_ephemeral_fields(schema))
                .unwrap_or_else(|| Ok(output.content.clone()))
        })
        .transpose()?;
    let (raw_output, hard_fail, fail_kind) = match (&result, &resolved_media_handoffs) {
        (Ok(_), Some(Err(error))) => (
            format!("Error: {error}"),
            true,
            Some(crate::engine::tool::ToolFailKind::Execution),
        ),
        (Ok(output), _) => (
            output
                .display_content
                .clone()
                .unwrap_or_else(|| output.content.model_text().to_owned()),
            false,
            None,
        ),
        (Err(e), _) => {
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
            let recent = env.session.recent_bash();
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
            env.session.push_recent_bash(command.to_string(), exit_code);
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
    if let Some(disclosure) = &verification_disclosure {
        if !output_str.ends_with('\n') {
            output_str.push('\n');
        }
        output_str.push_str(disclosure);
    }
    let output_before_recheck = output_str.clone();

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
        let recheck_ctx = ResultRecheckCtx::from_tool_ctx(env.ctx);
        output_str = match result_recheck(&output_str, &recheck_ctx, env.tx).await {
            Ok(output) => output,
            Err(error) => {
                release_tool_media_handoffs(&mut resolved_media_handoffs).await;
                return Err(error);
            }
        };
    }
    // `notify` is a human-only lane, but it can still carry copied untrusted
    // nested-tool output. Hold it until the enclosing result safety boundary
    // has run, and apply that same decision to each side-channel value before
    // it can reach durable notice persistence or a connected client.
    let mut notices = result
        .as_ref()
        .ok()
        .filter(|_| !hard_fail)
        .map(|output| output.notices.clone())
        .unwrap_or_default();
    if recheck_result {
        let recheck_ctx = ResultRecheckCtx::from_tool_ctx(env.ctx);
        for notice in &mut notices {
            *notice = result_recheck(notice, &recheck_ctx, env.tx).await?;
        }
    }
    let recheck_modified_output = output_str != output_before_recheck;

    let canonical_result_is_text_only = result.as_ref().is_ok_and(|output| {
        output.content.parts().iter().all(|part| {
            matches!(
                part,
                crate::typed_media_result::CanonicalToolResultContent::Text { .. }
            )
        })
    });
    let mut artifact_captures = (!hard_fail && canonical_result_is_text_only)
        .then(|| {
            let mut captures = result
                .as_ref()
                .ok()
                .map(|output| output.text_artifact_captures.clone())
                .unwrap_or_default();
            if let Some(capture) = result
                .as_ref()
                .ok()
                .and_then(|output| output.text_artifact_capture.clone())
            {
                captures.push(crate::engine::tool::ToolTextArtifactCapture {
                    lane: if result
                        .as_ref()
                        .ok()
                        .is_some_and(|output| output.text_artifact_model_ephemeral)
                    {
                        crate::engine::tool::ToolArtifactLane::Display
                    } else {
                        crate::engine::tool::ToolArtifactLane::Model
                    },
                    capture,
                    explicit: true,
                });
            }
            captures
        })
        .unwrap_or_default();
    // Artifacts are durable and retrievable, so every lane crosses the
    // outbound redaction boundary before admission. A replacement that grows
    // the body fails closed rather than corrupting host capture accounting.
    for retained in &mut artifact_captures {
        let scrubbed = env.ctx.redact.scrub(&retained.capture.content);
        if scrubbed.len() <= retained.capture.host_captured_bytes {
            retained.capture.content = scrubbed;
            retained.capture.stored_source_bytes = retained.capture.content.len();
        } else {
            retained.capture.content.clear();
            retained.capture.stored_source_bytes = 0;
        }
    }
    // The display body above can be capped well before an adversarial tail.
    // A durable artifact is a separate outbound surface, so a flagged result
    // must pass the same injection decision over the complete retained body
    // before it can be persisted or rendered into a frame.  Preserve host
    // capture counters; only the accepted post-safety body/accounting changes.
    let mut artifact_capture_recheck_unavailable = false;
    if recheck_result {
        let recheck_ctx = ResultRecheckCtx::from_tool_ctx(env.ctx);
        for retained in &mut artifact_captures {
            match crate::engine::agent::recheck::result_recheck_for_artifact_capture(
                &retained.capture.content,
                &recheck_ctx,
                env.tx,
            )
            .await?
            {
                Some(accepted) => {
                    retained.capture.content = env.ctx.redact.scrub(&accepted);
                    retained.capture.stored_source_bytes = retained.capture.content.len();
                }
                None => {
                    artifact_capture_recheck_unavailable = true;
                    break;
                }
            }
        }
    }
    if artifact_capture_recheck_unavailable {
        tracing::warn!(tool = %resolved_name, "discarding retained tool capture because result safety recheck was unavailable");
        artifact_captures.clear();
    }
    let artifact_spill_bytes = env
        .agent
        .context_policy
        .as_ref()
        .map(crate::agents::ContextPolicy::artifact_spill_bytes)
        .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_SPILL_BYTES);
    let artifact_preview_lines = env
        .agent
        .context_policy
        .as_ref()
        .map(crate::agents::ContextPolicy::artifact_preview_lines)
        .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
    // A tool may explicitly retain a body even when it falls below the
    // automatic spill threshold—for example, a host-capped result with a
    // small but otherwise inaccessible tail.  The threshold controls only
    // automatic capture of ordinary inline results, not the tool's explicit
    // durable artifact contract.
    if artifact_captures.is_empty()
        && resolved_name != "mcp"
        && canonical_result_is_text_only
        && result.as_ref().is_ok_and(|output| !output.truncated)
        && output_str.len() > artifact_spill_bytes
    {
        artifact_captures.push(crate::engine::tool::ToolTextArtifactCapture {
            lane: crate::engine::tool::ToolArtifactLane::Model,
            capture: crate::intel::budget::capture_text_artifact_body(&output_str),
            explicit: false,
        });
    }
    let artifact_captures = artifact_captures
        .into_iter()
        .filter(|retained| {
            crate::engine::agent::text_artifact_capture_is_persistable(
                resolved_name,
                Some(&retained.capture),
                &output_str,
                recheck_modified_output,
            ) && (retained.explicit || retained.capture.content.len() > artifact_spill_bytes)
        })
        .collect::<Vec<_>>();

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
    let providers = env.ctx.config.providers();
    let active_provider = env.session.active_provider();
    let active_model = env.session.active_model();
    // Responses has two durable provider handles: its output-item id (`fc_…`)
    // and its result-correlation call id (`call_…`). Rig keeps the former on
    // `provider.item_id` and exposes the latter as `tc.id`; store the output
    // item whenever it exists. Single-id/no-item wires retain the correlation
    // handle as the only available item fallback, while `provider.call_id`
    // below remains a separate durable field.
    let provider_item_id = tc
        .provider
        .as_ref()
        .and_then(|provider| provider.item_id.clone())
        .unwrap_or_else(|| tc.id.to_string());
    // Journal (or fail-closed scrub) the co-persisted audit row against the SAME
    // pinned `tool_frame()` the timeline events use — one frame drives both the
    // ToolCall event and this audit row, so they classify against identical
    // trust + table and can never disagree across the intervening awaits (finding
    // 7 TOCTOU / finding r11-3 / decision 12).
    let audit_target_trusted = tool_frame().resolved_trusted();
    // A secret-accepting tool may execute with its full arguments, but the
    // ordinary tool-call ledger is unencrypted and must receive only that
    // tool's safe projection. Project both forms independently so shape/name
    // recovery remains visible without ever persisting secret fields.
    let ledger_original = ordinary_ledger_args(env, resolved_name, &original);
    let ledger_wire = model_history_args(env, resolved_name, &args);
    scheduler_await_commit().await;
    if let Err(e) = env
        .session
        .record_tool_call_journaled(
            ToolCallRow {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                agent: env.agent.name.clone(),
                call_id: tc.id.to_string(),
                parent_call_id: None,
                parent_child_index: None,
                identity: crate::session::ToolCallProviderIdentity::from_provider_call(
                    active_provider.as_deref(),
                    active_model.as_deref(),
                    Some(&providers),
                    Some(env.model.current_wire_api()),
                    provider_item_id,
                    tc.provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                ),
                tool: resolved_name.to_string(),
                path: tool_path,
                mcp_server: None,
                original_input_json: ledger_original.clone(),
                wire_input_json: ledger_wire.clone(),
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
                shape_fingerprint: repair_fingerprint.clone(),
                hint: hint_value.clone(),
            },
            tool_session_table.as_ref(),
            audit_target_trusted,
        )
        .await
    {
        // Auditing must not break the live conversation. Log and
        // continue — the model still sees the tool result.
        tracing::warn!(error = %e, tool = %resolved_name, "persisting tool_call_event failed");
    }

    let canonical_history_output = result.as_ref().ok().and_then(|output| {
        (!hard_fail
            && output.content.has_non_text_content()
            && output
                .content
                .parts()
                .iter()
                .all(|part| !part.is_media_reference())
            && output_str == output.content.model_text())
        .then(|| {
            serde_json::to_value(
                model_result_contents
                    .as_ref()
                    .unwrap_or(&output.content)
                    .parts(),
            )
        })
    });
    let canonical_history_output = match canonical_history_output.transpose() {
        Ok(output) => output,
        Err(error) => {
            release_tool_media_handoffs(&mut resolved_media_handoffs).await;
            return Err(error.into());
        }
    };
    // A media reference cannot always be converted back to provider-native
    // rich contents on restart. Persist this already-projected text fallback
    // with the event so resume never falls back to the display/audit body.
    let canonical_history_text = result.as_ref().ok().map(|output| {
        model_result_contents
            .as_ref()
            .unwrap_or(&output.content)
            .model_text()
            .to_string()
    });

    // Timeline event (Part B), sourced from / consistent with the
    // `tool_call_events` audit row above. The `call_id` here is the
    // model's per-tool-call id (`tc.id`), which is distinct from the
    // round-trip `call_id` (above) — both correlations matter. The
    // `sandbox` sub-object is present only for `bash` (Part B); it flows
    // verbatim into `events.json` on export with no exporter change.
    let mut event_data = serde_json::json!({
        "tool": resolved_name,
        "original_input": ledger_original,
        "wire_input": ledger_wire,
        "recovery_kind": recovery_kind,
        "recovery_stage": recovery_stage,
        "hard_fail": hard_fail,
        "output": output_str.clone(),
        "truncated": truncated,
        "duration_ms": duration_ms,
    });
    if let Some(canonical_output) = &canonical_history_output {
        event_data["canonical_output"] = canonical_output.clone();
    }
    if let Some(canonical_output_text) = &canonical_history_text {
        event_data["canonical_output_text"] = canonical_output_text.clone().into();
    }
    if result.as_ref().ok().is_some_and(|output| {
        output.display_content.is_some()
            || model_result_contents
                .as_ref()
                .is_some_and(|projected| projected.parts() != output.content.parts())
    }) {
        event_data["model_projection_required"] = Value::Bool(true);
    }
    // Name-repair surfacing (§14): when the emitted tool NAME was repaired
    // (rebound or charset-sanitized), `tool` above is the wire/model form;
    // the original malformed name (from `NameRepair.original`) rides here
    // so the user timeline can show it with the recovery chip. Present
    // only when a name repair actually fired — a clean exact name omits it.
    if let Recovery::NameRepair { original: orig, .. } = &recovery {
        event_data["original_tool"] = serde_json::json!(orig);
    }
    if let Some(event_data) = event_data.as_object_mut() {
        event_data.extend(result_metadata.clone());
    }
    // Post-result hint (`engine::bash_hints`): the user-side `data.hint`
    // surface (`{ kind, text, severity }`), surfaced as a TUI chip and
    // ridden along on export with no schema change. Present only when a
    // rule fired on this `bash` call; the wire-side append lives on
    // `wire_output` below (wire-vs-user split, GOALS §14).
    if let Some(hint) = &hint_value {
        event_data["hint"] = hint.clone();
    }
    // Rejected-call event (export-audit fidelity): emitted just BEFORE the
    // (hard-fail) `tool_call` row so a hallucinated / unrepairable call is a
    // one-query check on its own event type, not conflated with execution
    // failures. The `tool_call` row still records the diagnostic the model
    // saw; this names *why* it never dispatched.
    if let Some(reason) = rejection_reason
        && let Err(e) = {
            env.session
                .record_event_with_model_frame(
                    crate::db::session_log::SessionEventKind::ToolRejected,
                    Some(&env.agent.name),
                    Some(&tc.id),
                    tool_frame(),
                    &serde_json::json!({
                        "tool": resolved_name,
                        "reason": reason,
                    }),
                )
                .await
        }
    {
        tracing::warn!(error = %e, tool = %resolved_name, "record tool_rejected event failed");
    }
    let mut model_artifact_frame = None;
    let mut human_artifact_notes = Vec::new();
    let tool_call_seq = if !artifact_captures.is_empty() {
        let mut display_slot = 0_i64;
        let mut attachment_slot = 0_i64;
        let mut staged = Vec::new();
        for retained in artifact_captures {
            let (relation, projection_slot, capture_reason) = match retained.lane {
                crate::engine::tool::ToolArtifactLane::Model => (
                    crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult,
                    Some(0),
                    crate::db::text_artifacts::CaptureReason::DisplayTruncation,
                ),
                crate::engine::tool::ToolArtifactLane::Display => {
                    let slot = display_slot;
                    display_slot += 1;
                    (
                        crate::db::text_artifacts::TextArtifactRelation::ToolResultDisplay,
                        Some(slot),
                        crate::db::text_artifacts::CaptureReason::DisplayTruncation,
                    )
                }
                crate::engine::tool::ToolArtifactLane::Attachment => {
                    let slot = attachment_slot;
                    attachment_slot += 1;
                    (
                        crate::db::text_artifacts::TextArtifactRelation::ToolResultAttachment,
                        Some(slot),
                        crate::db::text_artifacts::CaptureReason::ExplicitAttachment,
                    )
                }
            };
            let staged_at = chrono::Utc::now().timestamp_millis();
            let staged_blob_path = crate::text_artifact_blob::new_path(env.session.id);
            env.session
                .db
                .stage_text_artifact_blob_cleanup_intent(
                    staged_blob_path.clone(),
                    env.session.id,
                    staged_at,
                )
                .await
                .context("staging tool artifact blob cleanup")?;
            let blob_path =
                crate::text_artifact_blob::write_at(&staged_blob_path, &retained.capture.content)
                    .with_context(|| format!("spilling tool result for {resolved_name}"))?;
            let provenance_json = serde_json::json!({
                "agent_id": &env.agent.name,
                "tool": resolved_name,
                "call_id": &tc.id,
                "source": "tool_result",
                "preview_lines": artifact_preview_lines,
                "blob_path": blob_path,
            })
            .to_string();
            staged.push((
                crate::db::text_artifacts::TextArtifactCandidate {
                    relation,
                    projection_slot,
                    kind: crate::db::text_artifacts::TextArtifactKind::ToolResult,
                    capture_reason,
                    content: retained.capture.content,
                    host_captured_bytes: retained.capture.host_captured_bytes,
                    host_original_bytes: retained.capture.host_original_bytes,
                    host_dropped_bytes: retained.capture.host_dropped_bytes,
                    stored_source_bytes: retained.capture.stored_source_bytes,
                    provenance_json,
                    created_at: chrono::Utc::now().timestamp_millis(),
                },
                staged_blob_path,
            ));
        }
        let candidates = staged
            .iter()
            .map(|(candidate, _)| candidate.clone())
            .collect();
        let staged_blob_paths = staged.iter().map(|(_, path)| path.clone()).collect();
        let event = crate::db::text_artifacts::TextArtifactEventInput {
            session_id: env.session.id,
            kind: crate::db::session_log::SessionEventKind::ToolCall,
            agent: Some(env.agent.name.clone()),
            call_id: Some(tc.id.to_string()),
            context: Default::default(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            data_json: event_data.to_string(),
            artifacts: candidates,
            staged_blob_paths,
            unavailable_projection: None,
        };
        match env.session.db.record_event_with_text_artifacts(event).await {
            Ok(result) => {
                for ((candidate, blob_path), slot) in staged.into_iter().zip(result.slots) {
                    match slot.admission {
                        crate::db::text_artifacts::TextArtifactAdmission::Stored(artifact) => {
                            if candidate.relation
                                == crate::db::text_artifacts::TextArtifactRelation::ToolResultDisplay
                            {
                                human_artifact_notes.push(format!(
                                    "({} bytes spilled -> handle cockpit://session/{}/artifacts/{})",
                                    artifact.content_bytes,
                                    env.session.short_id(),
                                    artifact.artifact_id
                                ));
                            } else if candidate.relation
                                == crate::db::text_artifacts::TextArtifactRelation::ToolResultAttachment
                            {
                                human_artifact_notes.push(format!(
                                    "({} bytes attached -> handle cockpit://session/{}/artifacts/{})",
                                    artifact.content_bytes,
                                    env.session.short_id(),
                                    artifact.artifact_id
                                ));
                            }
                            if candidate.relation
                                == crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult
                            {
                                let preview_head = crate::engine::text_artifact_frame::utf8_preview_lines(
                                    &candidate.content,
                                    artifact_preview_lines,
                                );
                                model_artifact_frame = Some(if resolved_name == "mcp" {
                                    format!(
                                        "({} bytes spilled -> handle cockpit://session/{}/artifacts/{})",
                                        artifact.content_bytes,
                                        env.session.short_id(),
                                        artifact.artifact_id
                                    )
                                } else {
                                    crate::engine::text_artifact_frame::render_artifact_frame(
                                        &crate::engine::text_artifact_frame::ArtifactFrame {
                                            status: "available",
                                            reason: None,
                                            artifact_id: Some(artifact.artifact_id),
                                            kind: "tool_result",
                                            capture_reason: artifact.capture_reason.as_str(),
                                            provenance_json: &artifact.provenance_json,
                                            host_captured_bytes: artifact.host_captured_bytes,
                                            host_original_bytes: artifact.host_original_bytes,
                                            host_dropped_bytes: artifact.host_dropped_bytes,
                                            stored_source_bytes: artifact.stored_source_bytes,
                                            content_bytes: artifact.content_bytes,
                                            line_count: candidate.content.lines().count(),
                                            preview_head: &preview_head,
                                            preview_tail: "",
                                        },
                                    )
                                });
                            }
                        }
                        admission => {
                            if let Err(error) = crate::text_artifact_blob::remove(&blob_path) {
                                tracing::error!(%error, %blob_path, "rejected tool artifact blob cleanup failed");
                            }
                            let reason = match admission {
                                crate::db::text_artifacts::TextArtifactAdmission::ArtifactLimit => {
                                    "artifact_limit"
                                }
                                crate::db::text_artifacts::TextArtifactAdmission::SessionQuota => {
                                    "session_quota"
                                }
                                crate::db::text_artifacts::TextArtifactAdmission::Stored(_) => {
                                    unreachable!()
                                }
                            };
                            match candidate.relation {
                                crate::db::text_artifacts::TextArtifactRelation::ToolResultDisplay => {
                                    human_artifact_notes.push(format!(
                                        "({} bytes spilled but artifact is unavailable: {reason})",
                                        candidate.stored_source_bytes,
                                    ));
                                }
                                crate::db::text_artifacts::TextArtifactRelation::ToolResultAttachment => {
                                    human_artifact_notes.push(format!(
                                        "({} bytes attached but artifact is unavailable: {reason})",
                                        candidate.stored_source_bytes,
                                    ));
                                }
                                crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult => {
                                    model_artifact_frame = Some(render_unavailable_tool_artifact_frame(
                                        &candidate, reason,
                                    ));
                                }
                                _ => unreachable!("tool calls only admit tool-result artifact lanes"),
                            }
                        }
                    }
                }
                Some(result.event_seq)
            }
            Err(error) => {
                for (candidate, blob_path) in staged {
                    if let Err(cleanup_error) = crate::text_artifact_blob::remove(&blob_path) {
                        tracing::error!(%cleanup_error, %blob_path, "failed tool artifact blob cleanup after database error");
                    }
                    match candidate.relation {
                        crate::db::text_artifacts::TextArtifactRelation::ToolResultDisplay => {
                            human_artifact_notes.push(format!(
                                "({} bytes spilled but artifact persistence is unavailable)",
                                candidate.stored_source_bytes,
                            ));
                        }
                        crate::db::text_artifacts::TextArtifactRelation::ToolResultAttachment => {
                            human_artifact_notes.push(format!(
                                "({} bytes attached but artifact persistence is unavailable)",
                                candidate.stored_source_bytes,
                            ));
                        }
                        crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult => {
                            model_artifact_frame = Some(render_unavailable_tool_artifact_frame(
                                &candidate,
                                "persistence_unavailable",
                            ));
                        }
                        _ => unreachable!("tool calls only admit tool-result artifact lanes"),
                    }
                }
                tracing::warn!(%error, tool = %resolved_name, "tool artifact event composition failed");
                None
            }
        }
    } else {
        match env
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some(&env.agent.name),
                Some(&tc.id),
                tool_frame(),
                &event_data,
            )
            .await
        {
            Ok(seq) => Some(seq),
            Err(error) => {
                tracing::warn!(%error, tool = %resolved_name, "record tool_call event failed");
                None
            }
        }
    };
    if !human_artifact_notes.is_empty() {
        let notes = human_artifact_notes.join("\n");
        let append_notes = |body: &mut String| {
            if !body.is_empty() && !body.ends_with('\n') {
                body.push('\n');
            }
            body.push_str(&notes);
        };
        append_notes(&mut output_str);
        event_data["output"] = Value::String(output_str.clone());

        let display = result_metadata
            .entry("display".to_owned())
            .or_insert_with(|| Value::String(String::new()));
        if let Value::String(display) = display {
            append_notes(display);
            event_data["display"] = Value::String(display.clone());
        }
    }
    // The verification projection is an audit relation to this exact durable
    // ordinary ToolCall event. It must never create a second synthetic
    // `verification:*` tool-call pair. If the canonical event could not be
    // persisted after a host effect, settle unknown/suppressed rather than
    // claiming a committed projection without its source event.
    if let Some(plan) = verification_dispatch_plan.take() {
        let output_digest =
            crate::db::verification_ledger::VerificationDigest::of(output_str.as_bytes());
        let host_effect_unknown = matches!(
            &result,
            Ok(output) if output.host_effect_unknown
        );
        let settlement =
            verification_host_settlement(hard_fail, host_effect_unknown, tool_call_seq.is_some());
        let receipt = match settlement {
            crate::db::verification_ledger::DispatchSettlement::Failed => {
                crate::db::verification_ledger::RedactedVerificationJson::dispatch_final_error(
                    output_digest,
                )
            }
            crate::db::verification_ledger::DispatchSettlement::Succeeded => {
                crate::db::verification_ledger::RedactedVerificationJson::dispatch_success(
                    output_digest,
                )
            }
            crate::db::verification_ledger::DispatchSettlement::Unknown
            | crate::db::verification_ledger::DispatchSettlement::CancelledNoSubmission => {
                crate::db::verification_ledger::RedactedVerificationJson::dispatch_unknown(
                    output_digest,
                )
            }
        };
        let projection_event_seq = tool_call_seq;
        if let Err(error) = env
            .session
            .db
            .settle_verification_dispatch(
                env.session.id,
                plan.operation_id,
                plan.attempt_revision,
                settlement,
                receipt,
                projection_event_seq,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
        {
            tracing::warn!(%error, operation_id = %plan.operation_id, "verification dispatch settlement failed; recovery will reconcile it");
        }
    }
    if hard_fail && !verification_blocked {
        let _ = env
            .tx
            .send(TurnEvent::ToolError {
                agent: env.agent.name.clone(),
                call_id: tc.id.to_string(),
                tool: resolved_name.to_string(),
                error: event_data["output"].as_str().unwrap_or("").to_string(),
                kind: fail_kind.unwrap_or(crate::engine::tool::ToolFailKind::Execution),
                seq: tool_call_seq,
            })
            .await;
    } else {
        let _ = env
            .tx
            .send(TurnEvent::ToolEnd {
                agent: env.agent.name.clone(),
                call_id: tc.id.to_string(),
                tool: resolved_name.to_string(),
                output: event_data["output"].as_str().unwrap_or("").to_string(),
                truncated,
                seq: tool_call_seq,
                hint: bash_hint.as_ref().map(|h| h.user_chip.text.clone()),
            })
            .await;
    }
    for text in notices {
        let _ = env.tx.send(TurnEvent::Notice { text }).await;
    }
    if lifecycle_started {
        let lifecycle_status = if repeated_recoverable_tool_call_reject {
            "blocked_recoverable_repeat_guard"
        } else if loop_guard_reject {
            "blocked_loop_guard"
        } else if gate_blocked {
            gate_block_status
        } else if placeholder_blocked {
            "blocked_redaction_placeholder"
        } else if verification_blocked {
            "blocked_verification"
        } else if hard_fail {
            "failed"
        } else {
            "completed"
        };
        let dispatched = !(repeated_recoverable_tool_call_reject
            || loop_guard_reject
            || gate_blocked
            || placeholder_blocked
            || verification_blocked);
        let mut completed_data = serde_json::json!({
            "tool": resolved_name,
            "status": lifecycle_status,
            "dispatched": dispatched,
            "hard_fail": hard_fail,
            "output": event_data["output"].clone(),
            "truncated": truncated,
            "duration_ms": duration_ms,
        });
        if let Some(canonical_output) = &canonical_history_output {
            completed_data["canonical_output"] = canonical_output.clone();
        } else if let Ok(output) = &result
            && output
                .content
                .parts()
                .iter()
                .any(|part| part.is_media_reference())
        {
            // The provider dispatch failed closed, but the durable/export
            // event retains the authority-free reference metadata. No bytes,
            // paths, URLs, or prose placeholder are persisted.
            completed_data["canonical_output"] = match serde_json::to_value(output.content.parts())
            {
                Ok(output) => output,
                Err(error) => {
                    release_tool_media_handoffs(&mut resolved_media_handoffs).await;
                    return Err(error.into());
                }
            };
        }
        if let Some(canonical_output_text) = &canonical_history_text {
            completed_data["canonical_output_text"] = canonical_output_text.clone().into();
        }
        if let Some(completed_data) = completed_data.as_object_mut() {
            completed_data.extend(result_metadata.clone());
        }
        if let Some(hint) = &hint_value {
            completed_data["hint"] = hint.clone();
        }
        if let Err(e) = env
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::ToolCallCompleted,
                Some(&env.agent.name),
                Some(&tc.id),
                tool_frame(),
                &completed_data,
            )
            .await
        {
            tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_completed event failed");
        }
    }

    // `permissionDenied` observe hooks (Decision 3): fire AFTER the deny has
    // been recorded and audited (the `tool_call` row + `tool_call_completed`
    // event above) and BEFORE the rejected-tool diagnostic is returned to the
    // model. Observe-only / fail-open. The matcher is the resolved canonical
    // tool name; `permissionKind` is the existing deny status string.
    if let Some(permission_kind) = permission_denied_kind {
        fire_permission_denied_hook(env, resolved_name, &tc.id, permission_kind).await;
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
    let projected_output = model_result_contents
        .as_ref()
        .map(|content| content.model_text())
        .unwrap_or(&output_str);
    let model_result_metadata_suffix = match model_result_metadata {
        Value::Object(ref fields) if !fields.is_empty() => {
            serde_json::to_string(fields).context("serializing model-visible result fields")?
        }
        _ => String::new(),
    };
    let mut wire_output =
        if repair_hints.is_empty() || verification_blocked || verification_disclosure.is_some() {
            projected_output.to_string()
        } else {
            let mut prefixed = String::new();
            for hint in &repair_hints {
                prefixed.push_str("<repair_note>");
                prefixed.push_str(&repair::repair_note_for_prompt(hint));
                prefixed.push_str("</repair_note>\n");
            }
            prefixed.push_str(projected_output);
            prefixed
        };
    if !model_result_metadata_suffix.is_empty() {
        if !wire_output.is_empty() {
            wire_output.push('\n');
        }
        wire_output.push_str(&model_result_metadata_suffix);
    }
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
    // A typed artifact projection replaces the entire model body.  Resume
    // rebuilds the same tool result from the durable frame alone; appending a
    // frame to the live capped body would make a live turn and its replay
    // byte-different (and would leak the capped body back into model context).
    if let Some(frame) = model_artifact_frame {
        wire_output = frame;
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
    let resolved_handoffs = resolved_media_handoffs
        .take()
        .and_then(std::result::Result::ok)
        .unwrap_or_default();
    let mut held_media_leases = Vec::new();
    let history_message = if !hard_fail && !resolved_handoffs.is_empty() {
        let built = (|| -> Result<Message> {
            use anyhow::Context as _;
            use rig::message::MimeType as _;

            let output = result
                .as_ref()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let projected_content = model_result_contents.as_ref().unwrap_or(&output.content);
            anyhow::ensure!(
                output.content.parts().len() == projected_content.parts().len(),
                "model result projection changed media part cardinality"
            );
            let mut handoffs = resolved_handoffs.iter();
            let mut tool_contents = Vec::new();
            let mut adjacent = Vec::new();
            for (part, projected_part) in
                output.content.parts().iter().zip(projected_content.parts())
            {
                match (part, projected_part) {
                    (
                        crate::typed_media_result::CanonicalToolResultContent::Text { .. },
                        crate::typed_media_result::CanonicalToolResultContent::Text { text },
                    ) => {
                        tool_contents.push(rig::message::ToolResultContent::text(text.clone()));
                    }
                    (
                        crate::typed_media_result::CanonicalToolResultContent::Json { .. },
                        crate::typed_media_result::CanonicalToolResultContent::Json { value },
                    ) => {
                        tool_contents.push(rig::message::ToolResultContent::json(value.clone()));
                    }
                    (
                        crate::typed_media_result::CanonicalToolResultContent::MediaReference {
                            reference,
                        },
                        crate::typed_media_result::CanonicalToolResultContent::MediaReference {
                            ..
                        },
                    ) => {
                        let handoff = handoffs
                            .next()
                            .context("media_reference_unavailable: missing resolved handoff")?;
                        match &handoff.mapping {
                            crate::typed_media_result::ProviderRigMapping::AnthropicEmbeddedImage {
                                mime_type,
                                base64_bytes,
                                ..
                            } => {
                                let media_type = rig::message::ImageMediaType::from_mime_type(
                                    mime_type,
                                )
                                .context("media_reference_unavailable: unsupported image MIME")?;
                                tool_contents.push(
                                    rig::message::ToolResultContent::image_base64(
                                        base64_bytes.clone(),
                                        Some(media_type),
                                        None,
                                    ),
                                );
                            }
                            crate::typed_media_result::ProviderRigMapping::OpenAiAdjacentImage {
                                image_mime_type,
                                image_base64_bytes,
                                ..
                            } => {
                                tool_contents.push(rig::message::ToolResultContent::json(
                                    serde_json::to_value(reference)?,
                                ));
                                let media_type = rig::message::ImageMediaType::from_mime_type(
                                    image_mime_type,
                                )
                                .context("media_reference_unavailable: unsupported image MIME")?;
                                adjacent.push(rig::message::UserContent::image_base64(
                                    image_base64_bytes.clone(),
                                    Some(media_type),
                                    None,
                                ));
                            }
                            crate::typed_media_result::ProviderRigMapping::AdjacentAudio {
                                audio_mime_type,
                                audio_base64_bytes,
                                ..
                            } => {
                                tool_contents.push(rig::message::ToolResultContent::json(
                                    serde_json::to_value(reference)?,
                                ));
                                let media_type = rig::message::AudioMediaType::from_mime_type(
                                    audio_mime_type,
                                )
                                .context("media_reference_unavailable: unsupported audio MIME")?;
                                adjacent.push(rig::message::UserContent::audio(
                                    audio_base64_bytes.clone(),
                                    Some(media_type),
                                ));
                            }
                            crate::typed_media_result::ProviderRigMapping::AdjacentVideo {
                                video_mime_type,
                                video_base64_bytes,
                                ..
                            } => {
                                tool_contents.push(rig::message::ToolResultContent::json(
                                    serde_json::to_value(reference)?,
                                ));
                                let media_type = rig::message::VideoMediaType::from_mime_type(
                                    video_mime_type,
                                )
                                .context("media_reference_unavailable: unsupported video MIME")?;
                                adjacent.push(rig::message::UserContent::video(
                                    video_base64_bytes.clone(),
                                    Some(media_type),
                                ));
                            }
                            crate::typed_media_result::ProviderRigMapping::ImageSidecar { .. } => {
                                anyhow::bail!(
                                    "media_reference_unavailable: sidecar handoff is not installed"
                                );
                            }
                        }
                    }
                    _ => anyhow::bail!("model result projection changed media part kind"),
                }
            }
            anyhow::ensure!(
                handoffs.next().is_none(),
                "media_reference_unavailable: extra resolved handoff"
            );
            let mut content = vec![rig::message::UserContent::tool_result_for(
                tc.id.clone(),
                tc.provider.clone(),
                resolved_name,
                tool_contents,
            )];
            content.extend(adjacent);
            Ok(Message::User { content })
        })();
        for handoff in resolved_handoffs {
            if let Some(lease) = handoff.lease {
                held_media_leases.push(lease);
            }
        }
        match built {
            Ok(message) => message,
            Err(error) => {
                let release_now = chrono::Utc::now().timestamp_millis();
                for lease in held_media_leases.drain(..) {
                    let _ = lease.release(release_now).await;
                }
                return Err(error);
            }
        }
    } else {
        let wire_contents = match &result {
            Ok(output)
                if !hard_fail
                    && wire_output
                        == model_result_contents
                            .as_ref()
                            .unwrap_or(&output.content)
                            .model_text()
                    && model_result_contents
                        .as_ref()
                        .unwrap_or(&output.content)
                        .parts()
                        .iter()
                        .all(|part| !part.is_media_reference()) =>
            {
                model_result_contents
                    .as_ref()
                    .unwrap_or(&output.content)
                    .to_rig_contents()?
            }
            _ => vec![rig::message::ToolResultContent::text(wire_output)],
        };
        crate::engine::message::tool_result_message_for_contents(tc, resolved_name, wire_contents)
    };
    history.push(history_message);
    let release_now = chrono::Utc::now().timestamp_millis();
    let mut release_error = None;
    for lease in held_media_leases {
        if let Err(error) = lease.release(release_now).await {
            release_error = Some(error);
        }
    }
    if let Some(error) = release_error {
        return Err(error.context("releasing tool-result media lease after history handoff"));
    }
    // Model-visible write/edit args: stub large applied fields from prior
    // assistant turns now that their matching results are in history. This
    // live projection is pure and must not make a completed filesystem effect
    // depend on a best-effort audit read. The latest assistant message is
    // always left intact until a later turn settles it.
    crate::engine::write_edit_arg_elision::elide_applied_write_edit_args(history);
    Ok(())
}

fn render_unavailable_tool_artifact_frame(
    candidate: &crate::db::text_artifacts::TextArtifactCandidate,
    reason: &'static str,
) -> String {
    let (preview_head, preview_tail) =
        crate::engine::text_artifact_frame::utf8_preview_pair(&candidate.content);
    crate::engine::text_artifact_frame::render_artifact_frame(
        &crate::engine::text_artifact_frame::ArtifactFrame {
            status: "unavailable",
            reason: Some(reason),
            artifact_id: None,
            kind: "tool_result",
            capture_reason: candidate.capture_reason.as_str(),
            provenance_json: &candidate.provenance_json,
            host_captured_bytes: candidate.host_captured_bytes,
            host_original_bytes: candidate.host_original_bytes,
            host_dropped_bytes: candidate.host_dropped_bytes,
            stored_source_bytes: candidate.stored_source_bytes,
            content_bytes: candidate.content.len(),
            line_count: candidate.content.lines().count(),
            preview_head,
            preview_tail,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        approval::{Approver, store::GrantStore},
        config::extended::ApprovalMode,
        engine::tool::Tool as _,
    };
    use async_trait::async_trait;
    use rig::message::{AssistantContent, ToolFunction, ToolResultContent, UserContent};
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    #[test]
    fn timeout_or_cancel_after_executing_settles_unknown_not_succeeded() {
        use crate::db::verification_ledger::DispatchSettlement;
        assert_eq!(
            verification_host_settlement(false, true, true),
            DispatchSettlement::Unknown
        );
        assert_eq!(
            verification_host_settlement(true, true, true),
            DispatchSettlement::Failed
        );
        assert_eq!(
            verification_host_settlement(false, false, true),
            DispatchSettlement::Succeeded
        );
        assert_eq!(
            verification_host_settlement(false, true, false),
            DispatchSettlement::Unknown
        );
    }

    #[test]
    fn replay_refusal_terminalizes_every_reserved_verification_dispatch() {
        use crate::db::needs_attention::{InterruptVerificationMemo, InterruptVerificationOutcome};

        let memo = |outcome, dispatch_attempt_revision| InterruptVerificationMemo {
            operation_id: uuid::Uuid::nil(),
            dispatch_attempt_revision,
            outcome,
        };

        assert!(replay_memo_has_reserved_dispatch(&memo(
            InterruptVerificationOutcome::DispatchOriginal,
            4,
        )));
        assert!(replay_memo_has_reserved_dispatch(&memo(
            InterruptVerificationOutcome::Revise {
                args: serde_json::json!({ "path": "output.txt" }),
                disclosure: "selected revision".to_string(),
            },
            4,
        )));
        assert!(!replay_memo_has_reserved_dispatch(&memo(
            InterruptVerificationOutcome::Block {
                message: "blocked before dispatch".to_string(),
            },
            -1,
        )));
    }

    struct EchoTool;

    #[async_trait]
    impl crate::engine::tool::Tool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn description(&self) -> &str {
            "Echo test input."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "x-cockpit-aliases": ["message"]
                    }
                },
                "required": ["text"]
            })
        }

        async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text(
                args.get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ))
        }
    }

    struct LedgerProjectedTool;

    #[async_trait]
    impl crate::engine::tool::Tool for LedgerProjectedTool {
        fn name(&self) -> &str {
            "ledger_projected"
        }

        fn description(&self) -> &str {
            "Test-only secret-accepting tool."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": { "literal": { "type": "string" } },
                "required": ["literal"],
                "additionalProperties": false,
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("stored"))
        }

        fn ledger_args(&self, _args: &Value) -> Value {
            serde_json::json!({ "literal": "[sealed literal omitted]" })
        }
    }

    struct ModelEphemeralTool;

    #[async_trait]
    impl crate::engine::tool::Tool for ModelEphemeralTool {
        fn name(&self) -> &str {
            "model_ephemeral"
        }

        fn description(&self) -> &str {
            "Test-only model history projection tool."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "visible": { "type": "string" },
                    "secret": { "type": "string", "x-cockpit-model-ephemeral": true }
                }
            })
        }

        fn result_schema(&self) -> Value {
            serde_json::json!({
                "$defs": {
                    "result": {
                        "type": "object",
                        "properties": {
                            "visible": { "type": "string" },
                            "secret": { "type": "string", "x-cockpit-model-ephemeral": true },
                            "sandbox": { "type": "string" },
                            "resource": { "type": "string" },
                            "exit_code": { "type": "integer" },
                            "output_sidecar": { "type": "string" }
                        }
                    }
                },
                "$ref": "#/$defs/result"
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            ToolOutput::canonical(vec![
                crate::typed_media_result::CanonicalToolResultContent::Json {
                    value: serde_json::json!({
                        "visible": "kept result",
                        "secret": "result sentinel",
                        "sandbox": "native sandbox result",
                        "resource": "native resource result",
                        "exit_code": 73,
                        "output_sidecar": "native sidecar result"
                    }),
                },
            ])
            .map(|output| {
                output
                    .with_sandbox(crate::engine::tool::SandboxMeta {
                        enabled: true,
                        confined: true,
                        escalated: false,
                        escalation_preauthorized: false,
                        approval_scope_recorded: None,
                        unavailable_reason: Some("sandbox metadata sentinel".to_string()),
                        resource_profiles: Vec::new(),
                    })
                    .with_resource(crate::engine::tool::ResourceMeta {
                        declared: std::collections::BTreeMap::new(),
                        policy: std::collections::BTreeMap::new(),
                        reviewer: std::collections::BTreeMap::new(),
                        effective: std::collections::BTreeMap::new(),
                        scheduler_request_id: None,
                        scheduler_display_id: None,
                        lease_id: None,
                        queue_position: None,
                        queue_timeout_ms: None,
                        queued_at_ms: None,
                        acquired_at_ms: None,
                        wait_ms: None,
                        acquired: true,
                        released_on_drop: false,
                        error: Some("resource metadata sentinel".to_string()),
                    })
                    .with_exit_code(987_654_321)
                    .with_output_sidecar(crate::engine::tool::ToolOutputSidecar {
                        payload: serde_json::json!({"detail": "sidecar metadata sentinel"}),
                    })
                    .with_model_ephemeral_display("kept result\nmodel ephemeral display sentinel")
                    .with_model_ephemeral_text_artifact_capture(
                        crate::intel::budget::capture_text_artifact_body(
                            "model ephemeral artifact sentinel",
                        ),
                    )
            })
        }
    }

    struct ReadOnlyEchoTool;

    #[async_trait]
    impl crate::engine::tool::Tool for ReadOnlyEchoTool {
        fn name(&self) -> &str {
            "readonly_echo"
        }

        fn description(&self) -> &str {
            "Read-only echo test input."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" }
                },
                "required": ["text"]
            })
        }

        fn effect(&self) -> crate::engine::tool::ToolEffect {
            crate::engine::tool::ToolEffect::ReadOnly
        }

        async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text(
                args.get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ))
        }
    }

    struct NestedCaptureTool {
        received: Arc<Mutex<Option<Value>>>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for NestedCaptureTool {
        fn name(&self) -> &str {
            "nested_capture"
        }

        fn description(&self) -> &str {
            "Capture nested normalized arguments."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "outer": {
                        "type": "object",
                        "properties": {
                            "required": { "type": "string" },
                            "optional": { "type": "integer" }
                        },
                        "required": ["required"]
                    }
                },
                "required": ["outer"]
            })
        }

        async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            *self.received.lock().unwrap() = Some(args);
            Ok(ToolOutput::text("captured"))
        }
    }

    struct FailTool;

    #[async_trait]
    impl crate::engine::tool::Tool for FailTool {
        fn name(&self) -> &str {
            "fail"
        }

        fn description(&self) -> &str {
            "Fail for dispatch tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            anyhow::bail!("intentional failure")
        }
    }

    struct TruncatedTool;

    #[async_trait]
    impl crate::engine::tool::Tool for TruncatedTool {
        fn name(&self) -> &str {
            "big"
        }

        fn description(&self) -> &str {
            "Return truncated test output."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::truncated_text("large output"))
        }
    }

    struct ArtifactCaptureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for ArtifactCaptureTool {
        fn name(&self) -> &str {
            "big"
        }

        fn description(&self) -> &str {
            "Return truncated test output with a typed artifact capture."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::truncated_text("visible line\n[truncated]\n")
                .with_text_artifact_capture(crate::engine::tool::TextArtifactCapture {
                    content: "visible line\nhidden line\n".to_string(),
                    host_captured_bytes: "visible line\nhidden line\n".len(),
                    host_original_bytes: "visible line\nhidden line\n".len(),
                    host_dropped_bytes: 0,
                    stored_source_bytes: "visible line\nhidden line\n".len(),
                }))
        }
    }

    struct DisplayAndAttachmentsTool;

    #[async_trait]
    impl crate::engine::tool::Tool for DisplayAndAttachmentsTool {
        fn name(&self) -> &str {
            "mcp"
        }

        fn description(&self) -> &str {
            "Return a model projection plus display and explicit artifact lanes."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            let display_body = "display spill\n".repeat(
                crate::db::text_artifacts::DEFAULT_ARTIFACT_SPILL_BYTES / "display spill\n".len()
                    + 1,
            );
            let first_attachment = "first explicit attachment";
            let second_attachment = "second explicit attachment";
            Ok(ToolOutput::text("model projection")
                .with_model_ephemeral_display("model projection\n[display truncated]")
                .with_text_artifact_lane(
                    crate::engine::tool::ToolArtifactLane::Display,
                    crate::intel::budget::capture_text_artifact_body(&display_body),
                    false,
                )
                .with_text_artifact_lane(
                    crate::engine::tool::ToolArtifactLane::Attachment,
                    crate::intel::budget::capture_text_artifact_body(first_attachment),
                    true,
                )
                .with_text_artifact_lane(
                    crate::engine::tool::ToolArtifactLane::Attachment,
                    crate::intel::budget::capture_text_artifact_body(second_attachment),
                    true,
                ))
        }
    }

    struct RedactedArtifactCaptureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for RedactedArtifactCaptureTool {
        fn name(&self) -> &str {
            "redacted_big"
        }

        fn description(&self) -> &str {
            "Return a captured result containing an outbound-redacted value."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            let captured = "visible line\nsuper-secret-token-value\nhidden line\n".to_string();
            Ok(ToolOutput::truncated_text("visible line\n[truncated]\n")
                .with_text_artifact_capture(crate::engine::tool::TextArtifactCapture {
                    host_captured_bytes: captured.len(),
                    host_original_bytes: captured.len(),
                    host_dropped_bytes: 0,
                    stored_source_bytes: captured.len(),
                    content: captured,
                }))
        }
    }

    struct NamedArtifactCaptureTool {
        name: &'static str,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for NamedArtifactCaptureTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "Return a typed artifact capture for frame and tool tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            let captured = format!(
                "head line\n{}INJECTION_SENTINEL_ONLY_IN_RETAINED_TAIL\ntail line\n",
                "captured line\n".repeat(700),
            );
            Ok(
                ToolOutput::truncated_text("head line\n... [truncated]\ntail line\n")
                    .with_text_artifact_capture(crate::engine::tool::TextArtifactCapture {
                        host_captured_bytes: captured.len(),
                        host_original_bytes: captured.len(),
                        host_dropped_bytes: 0,
                        stored_source_bytes: captured.len(),
                        content: captured,
                    }),
            )
        }
    }

    struct PartialArtifactCaptureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for PartialArtifactCaptureTool {
        fn name(&self) -> &str {
            "big_partial"
        }

        fn description(&self) -> &str {
            "Return truncated test output with a host-dropped artifact capture."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::truncated_text("visible line\n[truncated]\n")
                .with_text_artifact_capture(crate::engine::tool::TextArtifactCapture {
                    content: "visible line\nhidden prefix".to_string(),
                    host_captured_bytes: "visible line\nhidden prefix".len(),
                    host_original_bytes: 10_000,
                    host_dropped_bytes: 10_000 - "visible line\nhidden prefix".len(),
                    stored_source_bytes: "visible line\nhidden prefix".len(),
                }))
        }
    }

    struct InterruptWaitTool;

    #[async_trait]
    impl crate::engine::tool::Tool for InterruptWaitTool {
        fn name(&self) -> &str {
            "interrupt_wait"
        }

        fn description(&self) -> &str {
            "Wait on an interrupt for dispatch parking tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
            let set = crate::daemon::proto::InterruptQuestionSet {
                questions: vec![crate::daemon::proto::InterruptQuestion::Single {
                    prompt: "Allow?".to_string(),
                    options: vec![crate::daemon::proto::InterruptOption {
                        id: "allow".to_string(),
                        label: "Allow".to_string(),
                        description: None,
                        secondary: false,
                    }],
                    allow_freetext: false,
                    command_detail: None,
                    permission: true,
                    approval_class: None,
                    sandbox_escalation: None,
                }],
            };
            let response = crate::engine::interrupt::raise_and_wait(
                &ctx.session.db,
                &ctx.interrupts,
                ctx.session.id,
                &ctx.agent_id,
                "interrupt wait",
                set,
                "interrupt wait test",
            )
            .await
            .into_response()?;
            Ok(ToolOutput::text(format!("{response:?}")))
        }
    }

    struct GatedInterruptWaitTool;

    #[async_trait]
    impl crate::engine::tool::Tool for GatedInterruptWaitTool {
        fn name(&self) -> &str {
            "bash"
        }

        fn description(&self) -> &str {
            "Bash-shaped interrupt waiter for gate replay tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                },
                "required": ["command"]
            })
        }

        async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
            let set = crate::daemon::proto::InterruptQuestionSet {
                questions: vec![crate::daemon::proto::InterruptQuestion::Single {
                    prompt: "Inner approval?".to_string(),
                    options: vec![crate::daemon::proto::InterruptOption {
                        id: "allow".to_string(),
                        label: "Allow".to_string(),
                        description: None,
                        secondary: false,
                    }],
                    allow_freetext: false,
                    command_detail: None,
                    permission: true,
                    approval_class: None,
                    sandbox_escalation: None,
                }],
            };
            let response = crate::engine::interrupt::raise_and_wait(
                &ctx.session.db,
                &ctx.interrupts,
                ctx.session.id,
                &ctx.agent_id,
                "inner approval",
                set,
                "gated interrupt wait test",
            )
            .await
            .into_response()?;
            Ok(ToolOutput::text(format!("{response:?}")))
        }
    }

    struct NeverCalledTool {
        name: &'static str,
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for NeverCalledTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "Fails the test if dispatch reaches the tool body."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "command": { "type": "string" },
                    "url": { "type": "string" }
                }
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.called.store(true, Ordering::SeqCst);
            anyhow::bail!("NeverCalledTool was dispatched")
        }
    }

    struct CapabilityUnavailableTool {
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for CapabilityUnavailableTool {
        fn name(&self) -> &str {
            "capability_unavailable_tool"
        }

        fn description(&self) -> &str {
            "Requires a deliberately absent test binary."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
            vec![crate::capabilities::BinaryRequirement::required(
                "cockpit-test-binary-that-is-deliberately-unavailable-4f59b779",
                crate::capabilities::CapabilityRemedy::prose("test-only requirement"),
            )]
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.called.store(true, Ordering::SeqCst);
            anyhow::bail!("CapabilityUnavailableTool was dispatched")
        }
    }

    struct IntegerOnlyTool {
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for IntegerOnlyTool {
        fn name(&self) -> &str {
            "number"
        }

        fn description(&self) -> &str {
            "Accepts only an integer count."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "count": { "type": "integer" }
                },
                "required": ["count"]
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.called.store(true, Ordering::SeqCst);
            Ok(ToolOutput::text("called"))
        }
    }

    struct BashFixtureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for BashFixtureTool {
        fn name(&self) -> &str {
            "bash"
        }

        fn description(&self) -> &str {
            "Synthetic bash output for dispatch assembly tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                },
                "required": ["command"]
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("stdout:\nbody\nstderr:\nerr\nexit: 1").with_exit_code(1))
        }
    }

    struct BashArtifactCaptureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for BashArtifactCaptureTool {
        fn name(&self) -> &str {
            "bash"
        }

        fn description(&self) -> &str {
            "Synthetic bash artifact capture for dispatch tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                },
                "required": ["command"]
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            let captured = format!("head line\n{}tail line\n", "captured line\n".repeat(700));
            Ok(
                ToolOutput::truncated_text("head line\n... [truncated]\ntail line\n")
                    .with_text_artifact_capture(crate::engine::tool::TextArtifactCapture {
                        host_captured_bytes: captured.len(),
                        host_original_bytes: captured.len(),
                        host_dropped_bytes: 0,
                        stored_source_bytes: captured.len(),
                        content: captured,
                    })
                    // This synthetic fixture models a successful shell run;
                    // `None` is the production representation of a signaled
                    // process and correctly receives the failure guard.
                    .with_exit_code(0),
            )
        }
    }

    fn test_model() -> Arc<Model> {
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                ..crate::config::providers::ProviderEntry::default()
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

    fn test_agent(tools: ToolBox) -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools,
            model: test_model(),
            params: ModelParams::default(),
            scan_tool_results: false,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Build".to_string(),
            write_scope: None,
            workspace_lease: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        }
    }

    fn tool_call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: rig::message::ToolCallId::new_or_mint("call-1".to_string()),
            provider: rig::message::ProviderCallId::new("provider-call-1".to_string()),
            function: ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    fn tool_ctx(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> ToolCtx {
        ToolCtx {
            agent_id: "Build".to_string(),
            allowed_knowledge_bases: None,
            executing_model_trusted: false,
            knowledge_access_trusted: false,
            caller_model: None,
            agent_instance_id: None,
            lock_identity: "Build".to_string().clone(),
            write_scope: None,
            dream_read_scope: std::sync::Arc::new(std::sync::RwLock::new(None)),
            workspace_lease: None,
            current_tool_call_id: None,
            current_tool_call_scope: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks: Arc::new(crate::locks::LockManager::in_memory(session.db.clone())),
            session,
            cwd: root.to_path_buf(),
            redact: Arc::new(RedactionTable::empty()),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver: None,
            image_generation_dispatch: None,
            transcription_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::from([
                "history_search".to_string()
            ])),
            mcp_builtin_registry: Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(
                Vec::new(),
            )),
            has_tree: false,
            has_bash: false,
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: None,
            media_authority: None,
            media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
            config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(root),
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::for_cwd(root),
        }
    }

    fn attached_interrupt_hub(session: &Session) -> Arc<crate::engine::interrupt::InterruptHub> {
        let (events, _receiver) = tokio::sync::broadcast::channel(16);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        Arc::new(crate::engine::interrupt::InterruptHub::new(
            events,
            redaction,
            Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            session.db.clone(),
            session.id,
        ))
    }

    fn tool_ctx_with_interrupts(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
        interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    ) -> ToolCtx {
        let mut ctx = tool_ctx(session, root, tx);
        ctx.interrupts = interrupts;
        ctx
    }

    fn tool_ctx_with_attached_approver(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
        interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    ) -> ToolCtx {
        let mut ctx = tool_ctx_with_interrupts(session.clone(), root, tx, interrupts.clone());
        let store = GrantStore::new(
            session.db.clone(),
            session.id,
            root.to_path_buf(),
            ctx.config.clone(),
        );
        ctx.approver = Some(Arc::new(Approver::new(
            store,
            session.db.clone(),
            session.id,
            "Build",
            interrupts,
        )));
        ctx
    }

    fn tool_ctx_with_approver(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> ToolCtx {
        let mut ctx = tool_ctx(session.clone(), root, tx);
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let store = GrantStore::new(
            session.db.clone(),
            session.id,
            root.to_path_buf(),
            ctx.config.clone(),
        );
        ctx.approver = Some(Arc::new(Approver::new(
            store,
            session.db.clone(),
            session.id,
            "Build",
            hub,
        )));
        ctx
    }

    fn test_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(
            Session::create_for_test(
                db,
                root.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        )
    }

    async fn seed_tool_artifact(
        session: &Arc<Session>,
        content: &str,
        call_id: &str,
    ) -> crate::db::text_artifacts::TextArtifact {
        let result = session
            .db
            .record_event_with_text_artifacts(crate::db::text_artifacts::TextArtifactEventInput {
                session_id: session.id,
                kind: crate::db::session_log::SessionEventKind::ToolCall,
                agent: Some("Build".to_owned()),
                call_id: Some(call_id.to_owned()),
                context: crate::db::text_artifacts::TextArtifactEventContext::default(),
                ts_ms: 1,
                data_json: serde_json::json!({ "output": "visible" }).to_string(),
                artifacts: vec![crate::db::text_artifacts::TextArtifactCandidate {
                    relation:
                        crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult,
                    projection_slot: Some(0),
                    kind: crate::db::text_artifacts::TextArtifactKind::ToolResult,
                    capture_reason: crate::db::text_artifacts::CaptureReason::DisplayTruncation,
                    content: content.to_owned(),
                    host_captured_bytes: content.len(),
                    host_original_bytes: content.len(),
                    host_dropped_bytes: 0,
                    stored_source_bytes: content.len(),
                    provenance_json: serde_json::json!({
                        "agent_id": "Build",
                        "tool": "synthetic",
                        "call_id": call_id,
                    })
                    .to_string(),
                    created_at: 1,
                }],
                staged_blob_paths: Vec::new(),
                unavailable_projection: None,
            })
            .await
            .unwrap();
        match result.slots.into_iter().next().unwrap().admission {
            crate::db::text_artifacts::TextArtifactAdmission::Stored(artifact) => artifact,
            other => panic!("expected stored test artifact, got {other:?}"),
        }
    }

    fn redaction_table(root: &std::path::Path, placeholder: &str) -> RedactionTable {
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: placeholder.to_string(),
            ..crate::config::extended::RedactConfig::default()
        };
        let env = HashMap::from([(
            "API_TOKEN".to_string(),
            "super-secret-token-value".to_string(),
        )]);
        RedactionTable::build_with_env_and_secrets(&cfg, root, &env, Vec::<(String, String)>::new())
            .unwrap()
    }

    async fn test_btw_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            root.to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let fork = db
            .create_btw_fork(parent.id, false)
            .await
            .expect("btw fork")
            .info;
        Arc::new(
            Session::resume_for_test(
                db,
                fork.session_id,
                crate::session::test_redaction_key_resolver(),
            )
            .expect("resume btw fork")
            .expect("btw fork row"),
        )
    }

    fn push_assistant_call(history: &mut Vec<Message>, call: &ToolCall) {
        history.push(Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(call.clone())],
        });
    }

    fn last_tool_result_text(history: &[Message]) -> String {
        let Some(Message::User { content }) = history.last() else {
            panic!("expected trailing tool result, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => result.content.iter().find_map(|result_part| {
                    if let ToolResultContent::Text(text) = result_part {
                        Some(text.text.clone())
                    } else {
                        None
                    }
                }),
                _ => None,
            })
            .expect("tool result text")
    }

    fn last_tool_result_json(history: &[Message]) -> Value {
        let Some(Message::User { content }) = history.last() else {
            panic!("expected trailing tool result, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => result.content.iter().find_map(|result_part| {
                    if let ToolResultContent::Json { value } = result_part {
                        Some(value.clone())
                    } else {
                        None
                    }
                }),
                _ => None,
            })
            .expect("tool result JSON")
    }

    fn history_has_tool_result(history: &[Message], call_id: &str) -> bool {
        history.iter().any(|message| match message {
            Message::User { content } => content.iter().any(|part| match part {
                UserContent::ToolResult(result) => result.call == call_id,
                _ => false,
            }),
            _ => false,
        })
    }

    async fn park_next_interrupt(
        db: crate::db::Db,
        session_id: Uuid,
        interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    ) {
        for _ in 0..100 {
            if let Some(row) = db
                .list_open_interrupts(session_id)
                .await
                .unwrap()
                .into_iter()
                .next()
            {
                assert!(interrupts.park(row.interrupt_id).await);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for interrupt to park");
    }

    async fn assert_parked_call_has_no_result(
        session: &Session,
        history: &[Message],
        call_id: &str,
    ) {
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert!(rows.is_empty(), "parked call recorded audit rows: {rows:?}");

        let events = session.db.list_session_events(session.id).await.unwrap();
        let tool_result_events: Vec<_> = events
            .iter()
            .filter(|event| {
                event.call_id.as_deref() == Some(call_id)
                    && matches!(event.kind.as_str(), "tool_call" | "tool_call_completed")
            })
            .collect();
        assert!(
            tool_result_events.is_empty(),
            "parked call recorded result events: {tool_result_events:?}"
        );
        assert!(
            events.iter().any(|event| {
                event.call_id.as_deref() == Some(call_id) && event.kind == "tool_call_started"
            }),
            "parked call should keep its pre-dispatch start event"
        );
        assert!(
            !history_has_tool_result(history, call_id),
            "parked call wrote a tool_result into history: {history:?}"
        );

        let open = session.db.list_open_interrupts(session.id).await.unwrap();
        assert_eq!(open.len(), 1);
        let row = &open[0];
        assert_eq!(
            row.state,
            crate::db::needs_attention::InterruptState::Parked
        );
        assert_eq!(
            row.parked.as_ref().map(|payload| payload.call_id.as_str()),
            Some(call_id)
        );
    }

    async fn parked_interrupt_id(session: &Session) -> Uuid {
        session
            .db
            .list_open_interrupts(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.state == crate::db::needs_attention::InterruptState::Parked)
            .map(|row| row.interrupt_id)
            .expect("parked interrupt row")
    }

    async fn parked_replay_question(
        session: &Session,
        interrupt_id: Uuid,
    ) -> crate::engine::interrupt::PreResolvedInterruptQuestion {
        let row = session
            .db
            .get_interrupt(interrupt_id)
            .await
            .unwrap()
            .expect("parked interrupt row");
        crate::engine::interrupt::PreResolvedInterruptQuestion {
            agent_instance_id: row.agent_instance_id,
            agent: row.agent_id,
            description: row.description,
            questions: row.questions.expect("parked interrupt question set"),
            occurrence: 1,
        }
    }

    fn assistant_call_args(history: &[Message]) -> Value {
        let Some(Message::Assistant { content, .. }) = history.first() else {
            panic!("expected assistant call, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| {
                if let AssistantContent::ToolCall(call) = part {
                    Some(call.function.arguments.clone())
                } else {
                    None
                }
            })
            .expect("assistant tool call")
    }

    #[tokio::test]
    async fn review_toolset_whitelisted() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "should not run" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        let result = last_tool_result_text(&history);
        assert!(result.contains("background skill review cannot call `echo`"));
        assert!(!result.contains("should not run"));
    }

    /// Build a registry with a single `permissionDenied` hook matched to
    /// `tool`. The command is deliberately unresolvable so the hook fails open
    /// (executable-not-found) WITHOUT spawning a real process — a `hook_run`
    /// row is still recorded, which is all the wiring assertion needs.
    fn permission_denied_registry(tool: &str) -> crate::config::extended::hooks::HookRegistry {
        use crate::config::extended::hooks::{HookEvent, HookOrigin, HookRegistry, ResolvedHook};
        HookRegistry {
            hooks: vec![ResolvedHook {
                event: HookEvent::PermissionDenied,
                matcher: Some([tool.to_string()].into_iter().collect()),
                command: vec!["cockpit-permission-hook-does-not-exist".to_string()],
                timeout_secs: 5,
                env: std::collections::BTreeMap::new(),
                origin: HookOrigin::for_test("project:abcdef0123456789:0"),
                source_config_path: std::path::PathBuf::from("/tmp/test/config.json"),
                source_directory: std::path::PathBuf::from("/tmp/test"),
                execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
            }],
            warnings: Vec::new(),
        }
    }

    async fn permission_denied_hook_tools(session: &Session) -> Vec<String> {
        session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "hook_run" && e.data["event"] == "permissionDenied")
            .map(|e| e.data["tool_name"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[tokio::test]
    async fn permission_denied_hook_fires_on_ordinary_tool_denial() {
        // A review-cage denial of an ordinary tool fires exactly one
        // `permissionDenied` hook_run row at the deny-audit site, matched on the
        // resolved tool name. On dead-code HEAD (no wiring) no such row exists,
        // so this fails there. A separate ALLOWED dispatch with the SAME hook
        // registered records NO `permissionDenied` row — proving the event
        // fires only on a real denial, never on the allow / pre-hook path.
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let model = test_model();
        let reg = permission_denied_registry("echo");

        // (a) Denied by the review cage → one permissionDenied row for `echo`.
        {
            let session = test_session(tmp.path());
            let (tx, _rx) = mpsc::channel(8);
            let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
            ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
            let env = DispatchEnv {
                agent: &agent,
                session: &session,
                model: &model,
                active_tools: &tools,
                ctx: &ctx,
                tx: &tx,
                hint_corrections: false,
                loop_guard_threshold: 10,
                hooks: &reg,
                cwd: tmp.path(),
            };
            let call = tool_call("echo", serde_json::json!({ "text": "should not run" }));
            let mut history = Vec::new();
            push_assistant_call(&mut history, &call);
            execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
                .await
                .unwrap();
            assert_eq!(
                permission_denied_hook_tools(&session).await,
                vec!["echo".to_string()],
                "a review-cage denial must fire exactly one permissionDenied hook for `echo`"
            );
        }

        // (b) Allowed dispatch (no cage) with the same hook registered → no
        // permissionDenied row. This covers the "never on the allow / pre-hook
        // path" contract: the pre-hook deny returns before the deny-audit site,
        // and a normal dispatch never classifies a permissionKind.
        {
            let session = test_session(tmp.path());
            let (tx, _rx) = mpsc::channel(8);
            let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
            let env = DispatchEnv {
                agent: &agent,
                session: &session,
                model: &model,
                active_tools: &tools,
                ctx: &ctx,
                tx: &tx,
                hint_corrections: false,
                loop_guard_threshold: 10,
                hooks: &reg,
                cwd: tmp.path(),
            };
            let call = tool_call("echo", serde_json::json!({ "text": "runs fine" }));
            let mut history = Vec::new();
            push_assistant_call(&mut history, &call);
            execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
                .await
                .unwrap();
            assert!(
                permission_denied_hook_tools(&session).await.is_empty(),
                "an allowed dispatch must not fire permissionDenied"
            );
        }
    }

    #[tokio::test]
    async fn placeholder_guard_precedes_schema_validation_in_ordinary_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(IntegerOnlyTool {
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("number", serde_json::json!({ "count": "[redacted]" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "number", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(!called.load(Ordering::SeqCst), "tool was not called");
        let result = last_tool_result_text(&history);
        assert!(result.contains("number"), "{result}");
        assert!(result.contains("count"), "{result}");
        assert!(result.contains("[redacted]"), "{result}");
        assert!(result.contains("redact.allowlist"), "{result}");
        assert!(result.contains("/toggle-redaction"), "{result}");
        assert!(
            !result.contains("schema validation"),
            "redaction remedy should win before schema validation: {result}"
        );
        let events = session.db.list_session_events(session.id).await.unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind == "notice"
                        && event.data["source"] == "redaction_placeholder_in_tool_args"
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn placeholder_guard_precedes_safety_gate_for_gated_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "bash",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Auto);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("bash", serde_json::json!({ "command": "cat [redacted]" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let _gate = set_safety_gate_test_override(GateOutcome::Parked);

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(!called.load(Ordering::SeqCst), "tool was not called");
        assert!(
            session
                .db
                .list_open_interrupts(session.id)
                .await
                .unwrap()
                .is_empty(),
            "placeholder block must not consult a parking safety gate"
        );
        let result = last_tool_result_text(&history);
        assert!(result.contains("bash"), "{result}");
        assert!(result.contains("command"), "{result}");
        assert!(result.contains("[redacted]"), "{result}");
        assert!(result.contains("redact.allowlist"), "{result}");
        assert!(result.contains("/toggle-redaction"), "{result}");
        let events = session.db.list_session_events(session.id).await.unwrap();
        let completed = events
            .iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(completed.data["status"], "blocked_redaction_placeholder");
        assert_eq!(completed.data["dispatched"], false);
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind == "notice"
                        && event.data["source"] == "redaction_placeholder_in_tool_args"
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn placeholder_guard_precedes_loop_guard_in_ordinary_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "echo",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 1,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "[redacted]" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(!called.load(Ordering::SeqCst), "tool was not called");
        let result = last_tool_result_text(&history);
        assert!(result.contains("redact.allowlist"), "{result}");
        assert!(
            !result.contains("Loop blocked"),
            "placeholder remedy should win before loop guard: {result}"
        );
        let completed = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(completed.data["status"], "blocked_redaction_placeholder");
        assert_eq!(completed.data["dispatched"], false);
    }

    #[tokio::test]
    async fn placeholder_guard_precedes_review_cage_in_ordinary_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "[redacted]" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        let result = last_tool_result_text(&history);
        assert!(result.contains("redact.allowlist"), "{result}");
        assert!(
            !result.contains("background skill review"),
            "placeholder remedy should win before review cage: {result}"
        );
        let completed = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(completed.data["status"], "blocked_redaction_placeholder");
        assert_eq!(completed.data["dispatched"], false);
    }

    #[tokio::test]
    async fn execute_ordinary_call_happy_path_records_events_audit_and_history() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "hello" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(history.len(), 2);
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolEnd { tool, output, .. }) if tool == "echo" && output == "hello")
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "echo");
        assert_eq!(rows[0].output, "hello");
    }

    #[tokio::test]
    async fn name_repaired_call_uses_executed_name_in_tool_result() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo_alias", serde_json::json!({ "text": "hello" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "echo",
            Recovery::NameRepair {
                stage: "rebind",
                original: "echo_alias".to_string(),
            },
            None,
        )
        .await
        .unwrap();

        let Message::Assistant { content, .. } = &history[0] else {
            panic!("expected repaired assistant call");
        };
        let AssistantContent::ToolCall(repaired_call) = &content[0] else {
            panic!("expected repaired tool call");
        };
        assert_eq!(repaired_call.function.name, "echo");

        let Message::User { content } = &history[1] else {
            panic!("expected tool result");
        };
        let UserContent::ToolResult(result) = &content[0] else {
            panic!("expected tool result content");
        };
        assert_eq!(result.call, call.id);
        assert_eq!(result.name, "echo");
    }

    #[tokio::test]
    async fn execute_ordinary_call_round_trips_responses_dual_identity_through_rehydrate() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = ToolCall::from_dual_wire(
            "fc_responses_item_1",
            "call_responses_1",
            ToolFunction {
                name: "echo".to_string(),
                arguments: serde_json::json!({ "text": "hello" }),
            },
        );
        assert_eq!(call.id, "call_responses_1");
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].call_id, "call_responses_1");
        assert_eq!(
            rows[0].provider_item_id.as_deref(),
            Some("fc_responses_item_1")
        );
        assert_eq!(
            rows[0].provider_call_id.as_deref(),
            Some("call_responses_1")
        );

        let rehydrated = crate::engine::rehydrate::rehydrate_session_with_policy(
            &session.db,
            session.id,
            "Build",
            crate::engine::rehydrate::RehydratePolicy::strict(),
        )
        .await
        .unwrap()
        .expect("recorded tool turn rehydrates");
        crate::engine::rehydrate::validate_pairing(&rehydrated.history)
            .expect("rehydrated tool result correlates with its call");

        let Message::Assistant { content, .. } = &rehydrated.history[0] else {
            panic!("expected rehydrated assistant tool call");
        };
        let rehydrated_call = content
            .iter()
            .find_map(|content| match content {
                AssistantContent::ToolCall(call) => Some(call),
                _ => None,
            })
            .expect("rehydrated tool call");
        assert_eq!(rehydrated_call.id, "call_responses_1");
        assert_eq!(
            rehydrated_call
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_responses_item_1")
        );
        assert_eq!(
            rehydrated_call
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_responses_1")
        );

        let Message::User { content } = &rehydrated.history[1] else {
            panic!("expected rehydrated tool result");
        };
        let rehydrated_result = content
            .iter()
            .find_map(|content| match content {
                UserContent::ToolResult(result) => Some(result),
                _ => None,
            })
            .expect("rehydrated tool result");
        assert_eq!(rehydrated_result.call, "call_responses_1");
        assert_eq!(
            rehydrated_result
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_responses_item_1")
        );
        assert_eq!(
            rehydrated_result
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_responses_1")
        );
    }

    /// Finding 7 (ordinary-path one-frame): the co-persisted audit row and the
    /// ToolCall session event are classified against ONE pinned authoring frame
    /// (`tool_frame()` = `env.model`), never the session's live/after-turn active
    /// model. Here the AUTHORING model (`env.model`) is TRUSTED and carries a
    /// secret-bearing table, while the session's active model is switched to an
    /// UNTRUSTED primary before the call. Both rows must still journal the secret
    /// and retain it RAW (consistent) — a regression to reading the session's
    /// active model (or building two frames that could diverge) would scrub one
    /// side while the other kept it raw.
    #[tokio::test]
    async fn execute_ordinary_call_audit_and_event_share_one_authoring_frame() {
        const SECRET: &str = "ordinary-path-secret-abc123456";
        let tmp = tempfile::tempdir().unwrap();
        // On-disk config: a TRUSTED authoring model (openai/gpt-5) and an
        // UNTRUSTED model (root/root-model) to switch the session's active model
        // to.
        let providers_dir = tmp.path().join(".cockpit").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();
        std::fs::write(tmp.path().join(".cockpit").join("config.json"), r#"{}"#).unwrap();
        std::fs::write(
            providers_dir.join("openai.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "gpt-5", "trust": "trusted", "mode": "frontier"}],
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            providers_dir.join("root.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "root-model", "trust": "untrusted", "mode": "defensive"}],
            })
            .to_string(),
        )
        .unwrap();

        // env.model = the TRUSTED authoring model, carrying a pre-policy session
        // table that contains SECRET.
        let redact_cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..crate::config::extended::RedactConfig::default()
        };
        let env_map = HashMap::from([("DEPLOY_TOKEN".to_string(), SECRET.to_string())]);
        let secret_table = RedactionTable::build_with_env_and_secrets(
            &redact_cfg,
            tmp.path(),
            &env_map,
            Vec::<(String, String)>::new(),
        )
        .unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let providers = config.snapshot().providers.clone();
        let model = Model::for_provider_with_env(
            &providers,
            "openai",
            "gpt-5",
            Arc::new(secret_table),
            |_| None,
        )
        .expect("trusted authoring model builds");

        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        // Switch the session's active model to the UNTRUSTED primary BEFORE the
        // call — the classification must still come from env.model, not this.
        session.set_active_model("root", "root-model").unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "echo",
            serde_json::json!({ "text": format!("deploy {SECRET}") }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        // One pinned frame classified BOTH rows trusted, so BOTH journal the
        // literal and retain it raw — despite the untrusted session active model.
        let sid = session.id.to_string();
        assert!(
            !session
                .db
                .protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "the trusted authoring frame journals the arg literal"
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let audit_raw = serde_json::to_string(&rows[0].original_input_json).unwrap();
        assert!(
            audit_raw.contains(SECRET),
            "the audit row retains the raw arg (classified trusted via env.model, not the untrusted primary)"
        );
        // The co-persisted ToolCall session event is classified the SAME (raw
        // retained) — proving both used the one pinned authoring frame.
        let events = session.db.list_session_events(session.id).await.unwrap();
        let tool_call_event = events
            .iter()
            .find(|e| e.kind == "tool_call")
            .expect("a ToolCall session event was recorded");
        let event_body = serde_json::to_string(&tool_call_event.data).unwrap();
        assert!(
            event_body.contains(SECRET),
            "the ToolCall event retains the raw arg — consistent with the audit row (one frame)"
        );
    }

    #[tokio::test]
    async fn secret_tool_projection_never_reaches_ordinary_durable_records() {
        const SECRET: &str = "ordinary-tool-ledger-secret";
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(LedgerProjectedTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("ledger_projected", serde_json::json!({ "literal": SECRET }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "ledger_projected",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(
            rx.recv().await,
            Some(TurnEvent::ToolStart { args, .. })
                if args == serde_json::json!({ "literal": "[sealed literal omitted]" })
        ));
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows.iter().all(|row| {
            !row.original_input_json.to_string().contains(SECRET)
                && !row.wire_input_json.to_string().contains(SECRET)
        }));
        assert_eq!(
            rows[0].original_input_json,
            serde_json::json!({ "literal": "[sealed literal omitted]" })
        );
        assert_eq!(rows[0].wire_input_json, rows[0].original_input_json);

        let events = session.db.list_session_events(session.id).await.unwrap();
        let durable_input_events: Vec<_> = events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind.as_str(),
                    "tool_call_started" | "tool_call" | "tool_call_completed"
                )
            })
            .collect();
        assert_eq!(durable_input_events.len(), 3);
        assert!(
            durable_input_events
                .iter()
                .all(|event| { !serde_json::to_string(&event.data).unwrap().contains(SECRET) })
        );
    }

    #[tokio::test]
    async fn btw_mutating_tool_requires_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "dynamic_tool",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Yolo);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("dynamic_tool", serde_json::json!({ "text": "blocked" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        let err = execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "dynamic_tool",
            Recovery::Clean,
            None,
        )
        .await
        .expect_err("btw dynamic tool must require approval");

        assert!(
            err.to_string()
                .contains(crate::approval::NONINTERACTIVE_RUN_DENIAL)
        );
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(history.len(), 1);
        assert!(
            session
                .db
                .list_tool_calls_for_session(session.id)
                .await
                .unwrap()
                .is_empty(),
            "denied pre-approval call must not be audited as executed"
        );
    }

    #[tokio::test]
    async fn revised_args_are_the_btw_native_authorization_target() {
        const REVISED_SENTINEL: &str = "verification-selected-btw-args";
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "dynamic_tool",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Manual);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let revised = serde_json::json!({"text": REVISED_SENTINEL});
        assert!(matches!(
            authorize_btw_native_call(&env, "dynamic_tool", &revised)
                .await
                .unwrap(),
            BtwNativeAuthorization::Refused { .. }
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn revised_args_are_the_repeat_confirmation_target() {
        const REVISED_SENTINEL: &str = "verification-selected-repeat-args";
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ReadOnlyEchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Manual);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 1,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let revised = serde_json::json!({"text": REVISED_SENTINEL});
        assert!(matches!(
            authorize_repeat_call(&env, "readonly_echo", &revised, true)
                .await
                .unwrap(),
            RepeatCallAuthorization::ConfirmationDenied { consecutive: 1 }
        ));
        let events = session.db.list_session_events(session.id).await.unwrap();
        let decisions = events
            .iter()
            .filter(|event| event.kind == "permission_decision")
            .map(|event| event.data.to_string())
            .collect::<Vec<_>>();
        assert!(
            decisions
                .iter()
                .any(|event| event.contains(REVISED_SENTINEL))
        );
    }

    #[tokio::test]
    async fn btw_mutating_tool_denial_fires_permission_denied_hook() {
        // A /btw side-conversation approval denial of a mutating ordinary tool
        // early-returns before the common deny-audit site, so it must fire
        // `permissionDenied` at the early-return arm. With no approver the btw
        // gate resolves to `NoninteractiveDeny`. On dead-code HEAD (no wiring at
        // the early-return arm) no permissionDenied row exists → this fails.
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "dynamic_tool",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Yolo);
        let model = test_model();
        let reg = permission_denied_registry("dynamic_tool");
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &reg,
            cwd: tmp.path(),
        };
        let call = tool_call("dynamic_tool", serde_json::json!({ "text": "blocked" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        let err = execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "dynamic_tool",
            Recovery::Clean,
            None,
        )
        .await
        .expect_err("btw dynamic tool must require approval");
        assert!(
            err.to_string()
                .contains(crate::approval::NONINTERACTIVE_RUN_DENIAL)
        );
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(
            permission_denied_hook_tools(&session).await,
            vec!["dynamic_tool".to_string()],
            "a /btw approval denial must fire exactly one permissionDenied hook"
        );
    }

    #[tokio::test]
    async fn btw_readonly_tool_uses_normal_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ReadOnlyEchoTool));
        let agent = test_agent(tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Yolo);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("readonly_echo", serde_json::json!({ "text": "allowed" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "readonly_echo",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert_eq!(last_tool_result_text(&history), "allowed");
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "readonly_echo");
    }

    #[tokio::test]
    async fn btw_fork_does_not_prompt_for_readonly_intel_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let read_only_tools = ToolBox::new().with(Arc::new(crate::tools::intel::GraphTool));
        let agent = test_agent(read_only_tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Yolo);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &read_only_tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("graph", serde_json::json!({ "kind": "recent", "limit": 1 }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "graph", Recovery::Clean, None)
            .await
            .expect("read-only intel tools intentionally do not prompt in /btw forks");

        assert!(history_has_tool_result(&history, &call.id));
        assert_eq!(
            session
                .db
                .list_tool_calls_for_session(session.id)
                .await
                .unwrap()
                .len(),
            1
        );

        let called = Arc::new(AtomicBool::new(false));
        let dynamic_tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "dynamic_tool",
            called: called.clone(),
        }));
        let agent = test_agent(dynamic_tools.clone());
        let session = test_btw_session(tmp.path()).await;
        session.set_approval_mode(ApprovalMode::Yolo);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &dynamic_tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("dynamic_tool", serde_json::json!({ "text": "blocked" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        let err = execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "dynamic_tool",
            Recovery::Clean,
            None,
        )
        .await
        .expect_err("dynamic tools still prompt in /btw forks");

        assert!(
            err.to_string()
                .contains(crate::approval::NONINTERACTIVE_RUN_DENIAL)
        );
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn execute_ordinary_call_strips_nested_wire_null_before_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let received = Arc::new(Mutex::new(None));
        let tools = ToolBox::new().with(Arc::new(NestedCaptureTool {
            received: received.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &agent.model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "nested_capture",
            serde_json::json!({
                "outer": { "required": "kept", "optional": null }
            }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "nested_capture",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            received.lock().unwrap().take().unwrap(),
            serde_json::json!({ "outer": { "required": "kept" } })
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "normalized call must reach real dispatch");
    }

    #[tokio::test]
    async fn park_interrupt_wait_tool_records_no_result() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let interrupts = attached_interrupt_hub(&session);
        let tools = ToolBox::new().with(Arc::new(InterruptWaitTool));
        let agent = test_agent(tools.clone());
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let ctx = tool_ctx_with_interrupts(session.clone(), tmp.path(), &tx, interrupts.clone());
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &agent.model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("interrupt_wait", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let parker = tokio::spawn(park_next_interrupt(
            session.db.clone(),
            session.id,
            interrupts,
        ));

        let err = execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "interrupt_wait",
            Recovery::Clean,
            None,
        )
        .await
        .expect_err("parked interrupt should abort dispatch");
        parker.await.unwrap();

        assert!(crate::engine::interrupt::is_parked(&err), "{err:#}");
        assert_eq!(history.len(), 1);
        assert_parked_call_has_no_result(&session, &history, &call.id).await;

        let interrupt_id = parked_interrupt_id(&session).await;
        let response = crate::daemon::proto::ResolveResponse::Single {
            selected_id: "allow".to_string(),
        };
        assert!(
            session
                .db
                .begin_parked_interrupt_execution(interrupt_id, &response)
                .await
                .unwrap()
        );
        assert!(
            !session
                .db
                .begin_parked_interrupt_execution(interrupt_id, &response)
                .await
                .unwrap(),
            "duplicate parked answer must not claim execution twice"
        );
        let question = parked_replay_question(&session, interrupt_id).await;
        crate::engine::interrupt::with_pre_resolved_interrupt_question(
            interrupt_id,
            response,
            question,
            async {
                execute_ordinary_call(
                    &env,
                    &mut history,
                    &call,
                    "interrupt_wait",
                    Recovery::Clean,
                    None,
                )
                .await
            },
        )
        .await
        .unwrap();
        assert_eq!(history.len(), 2);
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].call_id, call.id.as_str());
    }

    #[tokio::test]
    async fn park_question_tool_records_no_result() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let interrupts = attached_interrupt_hub(&session);
        let tools = ToolBox::new().with(Arc::new(crate::tools::question::QuestionTool));
        let agent = test_agent(tools.clone());
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let ctx =
            tool_ctx_with_attached_approver(session.clone(), tmp.path(), &tx, interrupts.clone());
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &agent.model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "question",
            serde_json::json!({
                "questions": [{
                    "type": "text",
                    "prompt": "What should happen next?"
                }]
            }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let parker = tokio::spawn(park_next_interrupt(
            session.db.clone(),
            session.id,
            interrupts,
        ));

        let err =
            execute_ordinary_call(&env, &mut history, &call, "question", Recovery::Clean, None)
                .await
                .expect_err("parked question should abort dispatch");
        parker.await.unwrap();

        assert!(crate::engine::interrupt::is_parked(&err), "{err:#}");
        assert_eq!(history.len(), 1);
        assert_parked_call_has_no_result(&session, &history, &call.id).await;

        let interrupt_id = parked_interrupt_id(&session).await;
        let response = crate::daemon::proto::ResolveResponse::Freetext {
            text: "continue".to_string(),
        };
        assert!(
            session
                .db
                .begin_parked_interrupt_execution(interrupt_id, &response)
                .await
                .unwrap()
        );
        assert!(
            !session
                .db
                .begin_parked_interrupt_execution(interrupt_id, &response)
                .await
                .unwrap(),
            "duplicate parked answer must not claim execution twice"
        );
        let question = parked_replay_question(&session, interrupt_id).await;
        crate::engine::interrupt::with_pre_resolved_interrupt_question(
            interrupt_id,
            response,
            question,
            async {
                execute_ordinary_call(&env, &mut history, &call, "question", Recovery::Clean, None)
                    .await
            },
        )
        .await
        .unwrap();
        assert_eq!(history.len(), 2);
        assert!(last_tool_result_text(&history).contains("continue"));
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].call_id, call.id.as_str());
    }

    #[tokio::test]
    async fn interrupt_replay_gate_memo_is_persisted_with_inner_park() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Auto);
        let interrupts = attached_interrupt_hub(&session);
        let tools = ToolBox::new().with(Arc::new(GatedInterruptWaitTool));
        let agent = test_agent(tools.clone());
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let ctx = tool_ctx_with_interrupts(session.clone(), tmp.path(), &tx, interrupts.clone());
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &agent.model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("bash", serde_json::json!({ "command": "echo inner" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let _gate = set_safety_gate_test_override(GateOutcome::Run { recheck: true });
        let parker = tokio::spawn(park_next_interrupt(
            session.db.clone(),
            session.id,
            interrupts,
        ));

        let err = execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .expect_err("inner prompt should park dispatch");
        parker.await.unwrap();

        assert!(crate::engine::interrupt::is_parked(&err), "{err:#}");
        let interrupt_id = parked_interrupt_id(&session).await;
        let row = session
            .db
            .get_interrupt(interrupt_id)
            .await
            .unwrap()
            .expect("parked inner approval row");
        let gate = row
            .parked
            .as_ref()
            .and_then(|payload| payload.gate)
            .expect("inner parked payload carries gate memo");
        assert!(gate.recheck_result);
    }

    #[tokio::test]
    async fn execute_ordinary_call_unknown_tool_records_rejection_without_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new();
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("missing", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "missing", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(history.len(), 2);
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "missing")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { tool, error, .. }) if tool == "missing" && error.contains("unknown tool"))
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "missing");
        assert!(rows[0].hard_fail);
        let rejected = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_rejected")
            .expect("tool_rejected event");
        assert_eq!(rejected.data["reason"], "not_in_advertised_set");
    }

    /// Issue #135: an advertised schema stays in the provider prefix even when
    /// its host capability disappears. A matching model call is therefore a
    /// call-time availability failure, never a hallucinated-tool rejection.
    #[tokio::test]
    async fn advertised_capability_unavailable_tool_returns_availability_result() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(CapabilityUnavailableTool {
            called: called.clone(),
        }));
        let tools = tools.apply_capabilities(
            &HashMap::new(),
            tmp.path(),
            crate::capabilities::ExecutionTarget::Host,
        );
        assert_eq!(
            tools.call_availability("capability_unavailable_tool"),
            crate::engine::tool::ToolCallAvailability::AdvertisedUnavailable,
            "the capability gate changes callability, not provider visibility"
        );
        assert!(
            tools
                .advertised_definitions(crate::agents::ToolSteering::Terse)
                .iter()
                .any(|definition| definition.name == "capability_unavailable_tool"),
            "the model receives the unavailable tool's stable schema"
        );

        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 1,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("capability_unavailable_tool", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "capability_unavailable_tool",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        push_assistant_call(&mut history, &call);
        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "capability_unavailable_tool",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            history.len(),
            4,
            "each unavailable call receives its own result"
        );
        assert!(
            last_tool_result_text(&history).contains("currently unavailable"),
            "a repeated unavailable call returns availability, not a loop refusal"
        );
        assert!(
            !last_tool_result_text(&history).contains("Loop blocked"),
            "unavailable calls must not enter the loop-guard approval path"
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "capability_unavailable_tool")
        );
        assert!(
            matches!(
                rx.recv().await,
                Some(TurnEvent::ToolError { tool, error, kind, .. })
                    if tool == "capability_unavailable_tool"
                        && kind == crate::engine::tool::ToolFailKind::Execution
                        && error.contains("currently unavailable")
            ),
            "unavailability is a call-time execution result"
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "capability_unavailable_tool")
        );
        assert!(
            matches!(
                rx.recv().await,
                Some(TurnEvent::ToolError { tool, error, kind, .. })
                    if tool == "capability_unavailable_tool"
                        && kind == crate::engine::tool::ToolFailKind::Execution
                        && error.contains("currently unavailable")
            ),
            "a repeated unavailable call remains a call-time execution result"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "an unavailable tool must not reach its backend"
        );

        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.hard_fail));
        assert!(
            session
                .db
                .list_session_events(session.id)
                .await
                .unwrap()
                .into_iter()
                .all(|event| event.kind != "tool_rejected"),
            "provider-advertised unavailable calls are not hallucinations"
        );
    }

    /// AC20 (`computer-coordinator-live-loop-and-dispatch-wiring.md` §4):
    /// generic Rig function-tool dispatch refuses a provider identifier
    /// reserved for the native computer-use tool — it is never executed as an
    /// ordinary tool and no backend receives input. The refusal is explicit
    /// (its own `reserved_native_computer_tool` rejection reason), not folded
    /// into the generic `not_in_advertised_set` hallucination reason.
    #[tokio::test]
    async fn computer_live_generic_rig_refuses_native_computer() {
        for reserved in ["computer", "computer_20251124", "computer_20250124"] {
            let tmp = tempfile::tempdir().unwrap();
            // Register a tool UNDER the reserved name: the guard must refuse the
            // call before dispatch even when the name resolves in the toolbox,
            // so the tool body is never reached (zero backend input).
            let called = Arc::new(AtomicBool::new(false));
            let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
                name: reserved,
                called: called.clone(),
            }));
            let agent = test_agent(tools.clone());
            let session = test_session(tmp.path());
            let model = test_model();
            let (tx, mut rx) = mpsc::channel(8);
            let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
            let env = DispatchEnv {
                agent: &agent,
                session: &session,
                model: &model,
                active_tools: &tools,
                ctx: &ctx,
                tx: &tx,
                hint_corrections: false,
                loop_guard_threshold: 10,
                hooks: &crate::config::extended::hooks::HookRegistry::default(),
                cwd: tmp.path(),
            };
            // Native computer JSON args must never be re-parsed here.
            let call = tool_call(reserved, serde_json::json!({ "action": "screenshot" }));
            let mut history = Vec::new();
            push_assistant_call(&mut history, &call);

            execute_ordinary_call(&env, &mut history, &call, reserved, Recovery::Clean, None)
                .await
                .unwrap();

            // Refused: the model gets exactly one tool_result and the call is
            // marked hard-fail.
            assert_eq!(history.len(), 2, "{reserved}: assistant call + tool_result");
            assert!(
                matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == reserved)
            );
            assert!(
                matches!(
                    rx.recv().await,
                    Some(TurnEvent::ToolError { tool, error, .. })
                        if tool == reserved
                            && error.contains("reserved for the provider-native computer-use tool")
                ),
                "{reserved}: reserved refusal surfaced to the model"
            );

            // Zero backend input: the tool body was never reached.
            assert!(
                !called.load(Ordering::SeqCst),
                "{reserved}: reserved name must not dispatch to the tool body"
            );

            let rows = session
                .db
                .list_tool_calls_for_session(session.id)
                .await
                .expect("tool audit rows load");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].tool, reserved);
            assert!(rows[0].hard_fail);

            let rejected = session
                .db
                .list_session_events(session.id)
                .await
                .unwrap()
                .into_iter()
                .find(|event| event.kind == "tool_rejected")
                .expect("tool_rejected event");
            assert_eq!(rejected.data["reason"], "reserved_native_computer_tool");
        }
    }

    #[tokio::test]
    async fn dispatch_loop_guard_reject_does_not_dispatch_and_collapses_wire_history() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "echo",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(16);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 1,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "again" }));
        let mut history = Vec::new();

        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 2);

        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            !called.load(Ordering::SeqCst),
            "loop-guard rejection must synthesize a result without dispatching"
        );
        assert_eq!(
            history.len(),
            2,
            "second contiguous loop rejection replaces the prior collapse pair"
        );
        let wire = last_tool_result_text(&history);
        assert!(wire.contains("Loop blocked"), "{wire}");
        assert!(wire.contains("called 2 times"), "{wire}");
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("Loop blocked"))
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("Loop blocked"))
        );
    }

    #[tokio::test]
    async fn dispatch_safety_gate_block_does_not_dispatch_and_uses_gate_result() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "bash",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Auto);
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "bash",
            serde_json::json!({ "command": "curl https://example.test" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let _gate = set_safety_gate_test_override(GateOutcome::Block(GateBlock {
            message: gate_block_message("bash", true),
            status: "blocked_safety_gate",
        }));

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            !called.load(Ordering::SeqCst),
            "safety-gate block must not dispatch the gated tool"
        );
        let wire = last_tool_result_text(&history);
        assert!(
            wire.contains("command-safety gate could not reach"),
            "{wire}"
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.tool, "bash");
        let event = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(event.data["status"], "blocked_safety_gate");
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "bash")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("command-safety gate"))
        );
    }

    #[tokio::test]
    async fn dispatch_standing_reject_gate_records_blocked_standing_reject() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "bash",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Auto);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let approver = ctx.approver.as_ref().unwrap();
        let classification = crate::approval::classify::classify("gh pr create");
        let info = classification.simple_commands().iter().next().unwrap();
        approver
            .store()
            .record_command_reject(info, crate::approval::store::Scope::Session)
            .await
            .unwrap();
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("bash", serde_json::json!({ "command": "gh pr create" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(!called.load(Ordering::SeqCst));
        let wire = last_tool_result_text(&history);
        assert!(wire.contains("rejected at session scope"), "{wire}");
        let event = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(event.data["status"], "blocked_standing_reject");
    }

    #[tokio::test]
    async fn dispatch_bash_wire_output_orders_failure_guard_body_nudge_then_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(BashFixtureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.push_recent_bash("rg foo src".to_string(), Some(1));
        session.push_recent_bash("rg foo src | grep -v one".to_string(), Some(1));
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "bash",
            serde_json::json!({ "command": "rg foo src | grep -v one | grep -v two" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        let wire = last_tool_result_text(&history);
        let guard = wire.find("FAILED (exit 1)").expect("failure guard");
        let body = wire.find("stdout:\nbody").expect("bash body");
        let nudge = wire
            .find("This command FAILED (exit 1)")
            .expect("failure nudge");
        let hint = wire
            .find("--- hint(filter_refinement_loop):")
            .expect("bash hint");
        assert_eq!(guard, 0, "{wire}");
        assert!(guard < body && body < nudge && nudge < hint, "{wire}");
    }

    #[tokio::test]
    async fn execute_ordinary_call_shape_repair_rewrites_history_and_wire_note_only() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: true,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "message": "hello" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(
            assistant_call_args(&history),
            serde_json::json!({ "text": "hello" })
        );
        let wire_result = last_tool_result_text(&history);
        assert!(wire_result.contains("<repair_note>"), "{wire_result}");
        assert!(wire_result.ends_with("hello"), "{wire_result}");
        assert!(matches!(rx.recv().await, Some(TurnEvent::ToolStart { .. })));
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolEnd { output, .. }) if output == "hello")
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            row.original_input_json,
            serde_json::json!({ "message": "hello" })
        );
        assert_eq!(row.wire_input_json, serde_json::json!({ "text": "hello" }));
        assert_eq!(row.output, "hello");
    }

    #[tokio::test]
    async fn model_ephemeral_fields_are_bounded_in_live_and_restart_history() {
        const ARG_SECRET: &str = "argument sentinel";
        const RESULT_SECRET: &str = "result sentinel";
        const SANDBOX_SECRET: &str = "sandbox metadata sentinel";
        const RESOURCE_SECRET: &str = "resource metadata sentinel";
        const SIDECAR_SECRET: &str = "sidecar metadata sentinel";
        const DISPLAY_ONLY: &str = "model ephemeral display sentinel";
        const ARTIFACT_ONLY: &str = "model ephemeral artifact sentinel";
        const NATIVE_SANDBOX: &str = "native sandbox result";
        const NATIVE_RESOURCE: &str = "native resource result";
        const NATIVE_SIDECAR: &str = "native sidecar result";
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ModelEphemeralTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "model_ephemeral",
            serde_json::json!({"visible": "kept argument", "secret": ARG_SECRET}),
        );
        let mut live_history = Vec::new();
        push_assistant_call(&mut live_history, &call);

        execute_ordinary_call(
            &env,
            &mut live_history,
            &call,
            "model_ephemeral",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        let live_wire = format!("{live_history:?}");
        assert!(!live_wire.contains(ARG_SECRET), "{live_wire}");
        assert!(!live_wire.contains(RESULT_SECRET), "{live_wire}");
        assert!(!live_wire.contains(SANDBOX_SECRET), "{live_wire}");
        assert!(!live_wire.contains(RESOURCE_SECRET), "{live_wire}");
        assert!(!live_wire.contains(SIDECAR_SECRET), "{live_wire}");
        assert!(!live_wire.contains(DISPLAY_ONLY), "{live_wire}");
        assert!(!live_wire.contains(ARTIFACT_ONLY), "{live_wire}");
        assert!(!live_wire.contains("987654321"), "{live_wire}");
        assert!(live_wire.contains(NATIVE_SANDBOX), "{live_wire}");
        assert!(live_wire.contains(NATIVE_RESOURCE), "{live_wire}");
        assert!(live_wire.contains(NATIVE_SIDECAR), "{live_wire}");
        assert_eq!(last_tool_result_json(&live_history)["exit_code"], 73);
        assert_eq!(
            assistant_call_args(&live_history),
            serde_json::json!({"visible": "kept argument"})
        );

        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.original_input_json["secret"], ARG_SECRET);
        assert!(row.wire_input_json.get("secret").is_none());
        assert!(row.output.contains(DISPLAY_ONLY), "{}", row.output);
        let event = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call")
            .unwrap();
        assert!(event.data.to_string().contains(RESULT_SECRET));
        assert!(event.data.to_string().contains(SANDBOX_SECRET));
        assert!(event.data.to_string().contains(RESOURCE_SECRET));
        assert!(event.data.to_string().contains(SIDECAR_SECRET));
        assert!(event.data.to_string().contains(DISPLAY_ONLY));
        assert_eq!(event.data["exit_code"], 987_654_321);
        assert_eq!(event.data["model_projection_required"], true);
        assert!(
            !event.data["canonical_output_text"]
                .to_string()
                .contains(RESULT_SECRET)
        );
        assert!(
            event.data["canonical_output_text"]
                .to_string()
                .contains(NATIVE_SANDBOX)
        );

        let restarted =
            crate::engine::rehydrate::rehydrate_session(&session.db, session.id, "Build")
                .await
                .unwrap()
                .unwrap();
        let restart_wire = format!("{:?}", restarted.history);
        assert!(!restart_wire.contains(ARG_SECRET), "{restart_wire}");
        assert!(!restart_wire.contains(RESULT_SECRET), "{restart_wire}");
        assert!(!restart_wire.contains(SANDBOX_SECRET), "{restart_wire}");
        assert!(!restart_wire.contains(RESOURCE_SECRET), "{restart_wire}");
        assert!(!restart_wire.contains(SIDECAR_SECRET), "{restart_wire}");
        assert!(!restart_wire.contains(DISPLAY_ONLY), "{restart_wire}");
        assert!(!restart_wire.contains(ARTIFACT_ONLY), "{restart_wire}");
        assert!(!restart_wire.contains("987654321"), "{restart_wire}");
        assert!(restart_wire.contains("kept argument"), "{restart_wire}");
        assert!(restart_wire.contains("kept result"), "{restart_wire}");
        assert!(restart_wire.contains(NATIVE_SANDBOX), "{restart_wire}");
        assert!(restart_wire.contains(NATIVE_RESOURCE), "{restart_wire}");
        assert!(restart_wire.contains(NATIVE_SIDECAR), "{restart_wire}");
        let artifacts = session.db.list_text_artifacts(session.id).await.unwrap();
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.content == ARTIFACT_ONLY)
        );
        assert_eq!(last_tool_result_json(&restarted.history)["exit_code"], 73);
    }

    #[tokio::test]
    async fn execute_ordinary_call_hard_fail_records_tool_error_and_audit_row() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(FailTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("fail", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "fail", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "fail")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("intentional failure"))
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.tool, "fail");
        assert!(row.hard_fail);
        assert!(row.output.contains("intentional failure"));
    }

    #[tokio::test]
    async fn captured_tool_result_emits_a_typed_artifact_frame() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("big", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "big", Recovery::Clean, None)
            .await
            .unwrap();

        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert!(row.truncated);
        assert_eq!(row.output, "visible line\n[truncated]\n");
        let wire = last_tool_result_text(&history);
        assert!(wire.contains("<cockpit_artifact_v1"), "{wire}");
        assert!(wire.contains("\"status\":\"available\""), "{wire}");
        assert!(wire.contains("\"kind\":\"tool_result\""), "{wire}");
    }

    #[tokio::test]
    async fn tool_result_artifact_live_projection_is_byte_identical_to_rehydrate() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("big", serde_json::json!({}));
        let mut live_history = Vec::new();
        push_assistant_call(&mut live_history, &call);

        execute_ordinary_call(&env, &mut live_history, &call, "big", Recovery::Clean, None)
            .await
            .unwrap();

        let live = last_tool_result_text(&live_history);
        assert!(
            live.starts_with("<cockpit_artifact_v1 payload_utf8_bytes="),
            "{live}"
        );
        assert!(
            !live.starts_with("visible line\n[truncated]\n"),
            "an artifact frame must replace, not append to, the capped live body: {live}"
        );

        let replayed =
            crate::engine::rehydrate::rehydrate_session(&session.db, session.id, "Build")
                .await
                .unwrap()
                .expect("the durable tool turn rehydrates");
        let replay = last_tool_result_text(&replayed.history);
        assert_eq!(
            live, replay,
            "live and restart/replay tool-result bytes must use one frame composition"
        );
    }

    #[tokio::test]
    async fn display_spills_and_explicit_attachments_surface_distinct_human_handles() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(DisplayAndAttachmentsTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("mcp", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "mcp", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "mcp")
        );
        let Some(TurnEvent::ToolEnd { output, .. }) = rx.recv().await else {
            panic!("mcp ToolEnd event");
        };
        assert!(
            output.contains("bytes spilled -> handle cockpit://session/"),
            "{output}"
        );
        assert_eq!(
            output
                .matches("bytes attached -> handle cockpit://session/")
                .count(),
            2,
            "{output}"
        );

        let wire = last_tool_result_text(&history);
        assert_eq!(wire, "model projection");
        assert!(!wire.contains("cockpit://"), "{wire}");

        let artifacts = session.db.list_text_artifacts(session.id).await.unwrap();
        assert_eq!(
            artifacts
                .iter()
                .filter(|artifact| {
                    artifact.relation
                        == crate::db::text_artifacts::TextArtifactRelation::ToolResultDisplay
                })
                .count(),
            1
        );
        assert_eq!(
            artifacts
                .iter()
                .filter(|artifact| {
                    artifact.relation
                        == crate::db::text_artifacts::TextArtifactRelation::ToolResultAttachment
                })
                .count(),
            2
        );
        let completed = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("completed tool event");
        assert_eq!(
            completed.data["output"].as_str().expect("completed output"),
            output
        );
    }

    fn long_write_content() -> String {
        let mut s = String::new();
        while crate::tokens::count(&s) < 140 {
            s.push_str(
                "fn example() { let value = expensive_computation(); println!(\"{value}\"); }\n",
            );
        }
        s
    }

    fn write_call_args(history: &[Message]) -> Value {
        for msg in history {
            let Message::Assistant { content, .. } = msg else {
                continue;
            };
            for part in content {
                if let AssistantContent::ToolCall(tc) = part
                    && tc.function.name == "write"
                {
                    return tc.function.arguments.clone();
                }
            }
        }
        panic!("write tool call not found in history: {history:?}");
    }

    fn first_tool_call(history: &[Message]) -> &ToolCall {
        history
            .iter()
            .find_map(|message| match message {
                Message::Assistant { content, .. } => content.iter().find_map(|part| match part {
                    AssistantContent::ToolCall(call) => Some(call),
                    _ => None,
                }),
                _ => None,
            })
            .expect("tool call in history")
    }

    #[tokio::test]
    async fn settled_write_arg_elision_is_byte_identical_live_and_on_rehydrate() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(crate::tools::write::WriteTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let content = long_write_content();
        let args = serde_json::json!({ "path": "big.rs", "content": content });
        let call = tool_call("write", args.clone());
        let mut live_history = Vec::new();
        push_assistant_call(&mut live_history, &call);

        execute_ordinary_call(
            &env,
            &mut live_history,
            &call,
            "write",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            write_call_args(&live_history)["content"],
            serde_json::json!(content)
        );

        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].wire_input_json["content"],
            serde_json::json!(content),
            "durable audit rows keep full args"
        );
        assert_eq!(
            rows[0].original_input_json["content"],
            serde_json::json!(content)
        );

        live_history.push(Message::Assistant {
            id: None,
            content: vec![AssistantContent::text("newer assistant turn")],
        });
        assert_eq!(
            crate::engine::write_edit_arg_elision::elide_applied_write_edit_args(&mut live_history),
            1
        );
        let live_args = write_call_args(&live_history);
        assert_eq!(live_args["path"], serde_json::json!("big.rs"));
        assert_eq!(
            live_args["content"],
            serde_json::json!(crate::engine::write_edit_arg_elision::applied_marker(
                content.len()
            ))
        );
        session
            .record_event(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("next-inference"),
                &serde_json::json!({ "text": "newer assistant turn" }),
            )
            .await
            .unwrap();

        let replayed =
            crate::engine::rehydrate::rehydrate_session(&session.db, session.id, "Build")
                .await
                .unwrap()
                .expect("the durable write turn rehydrates");
        let replay_args = write_call_args(&replayed.history);
        assert_eq!(
            serde_json::to_vec(&live_args).unwrap(),
            serde_json::to_vec(&replay_args).unwrap(),
            "live and restart/replay write args must use one projection"
        );
    }

    fn push_signed_assistant_call(history: &mut Vec<Message>, call: &ToolCall) {
        history.push(Message::Assistant {
            id: None,
            content: vec![
                AssistantContent::Reasoning(rig::message::Reasoning::new_with_signature(
                    "provider signed thinking",
                    Some("sig-native".into()),
                )),
                AssistantContent::ToolCall(call.clone()),
            ],
        });
    }

    #[tokio::test]
    async fn signed_name_repaired_write_is_not_elided_by_later_ordinary_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new()
            .with(Arc::new(crate::tools::write::WriteTool))
            .with(Arc::new(crate::tools::read::ReadTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let content = long_write_content();
        let args = serde_json::json!({ "path": "signed.rs", "content": content });
        let call = tool_call("Write", args.clone());
        let mut history = Vec::new();
        push_signed_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "write",
            Recovery::NameRepair {
                stage: "case_fold",
                original: "Write".to_string(),
            },
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            first_tool_call(&history).function.arguments["content"],
            serde_json::json!(content),
            "signed latest assistant must not be rewritten"
        );
        assert_eq!(first_tool_call(&history).function.name, "Write");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("signed.rs")).unwrap(),
            content
        );

        let follow_up = tool_call("read", serde_json::json!({ "path": "signed.rs" }));
        push_assistant_call(&mut history, &follow_up);
        execute_ordinary_call(
            &env,
            &mut history,
            &follow_up,
            "read",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        assert_eq!(first_tool_call(&history).function.name, "Write");
        assert_eq!(
            first_tool_call(&history).function.arguments["content"],
            serde_json::json!(content),
            "ordinary dispatch must defer settled signed calls to canonical inference reconciliation"
        );

        assert_eq!(
            crate::engine::write_edit_arg_elision::reconcile_deferred_signed_turns_and_elide(
                &session,
                "Build",
                &mut history,
                None,
            )
            .await,
            1
        );
        assert_eq!(first_tool_call(&history).function.name, "write");
        assert_eq!(
            write_call_args(&history)["content"],
            serde_json::json!(crate::engine::write_edit_arg_elision::applied_marker(
                content.len()
            ))
        );
    }

    #[tokio::test]
    async fn captured_tool_result_persists_only_the_post_safety_body() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(RedactedArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("redacted_big", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "redacted_big",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        let stored = session.db.list_text_artifacts(session.id).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].content.contains("super-secret-token-value"));
        assert!(stored[0].content.contains("[redacted]"));
        assert!(stored[0].stored_source_bytes < stored[0].host_captured_bytes);
        assert!(!last_tool_result_text(&history).contains("super-secret-token-value"));
    }

    #[tokio::test]
    async fn captured_tool_result_is_owned_by_the_same_session_event() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(ArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("big", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "big", Recovery::Clean, None)
            .await
            .unwrap();

        let stored = session.db.list_text_artifacts(session.id).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].kind,
            crate::db::text_artifacts::TextArtifactKind::ToolResult
        );
        assert_eq!(
            stored[0].relation,
            crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult
        );
        assert!(stored[0].content.contains("visible line"));
        assert!(stored[0].content.contains("hidden line"));
        let projection = last_tool_result_text(&history);
        assert!(
            projection.starts_with("<cockpit_artifact_v1 payload_utf8_bytes="),
            "{projection}"
        );
        // This deliberately small capture fits in the deterministic artifact
        // preview, so its retained line is model-visible without duplicating
        // the persisted payload in the tool-result event.
        assert!(projection.contains("hidden line"), "{projection}");
    }

    #[tokio::test]
    async fn bash_artifact_frame_is_readable_by_id() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(BashArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("bash", serde_json::json!({ "command": "synthetic" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        let artifact = session
            .db
            .list_text_artifacts(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let retrieved = crate::tools::recall::read(
            &serde_json::json!({
                "path": format!(
                    "cockpit://session/{}/artifacts/{}",
                    session.short_id(),
                    artifact.artifact_id
                )
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert!(retrieved.content.starts_with("1|head line\n"));
        assert!(retrieved.content.len() > "head line\n... [truncated]\ntail line\n".len());
    }

    #[tokio::test]
    async fn unavailable_full_capture_recheck_discards_tail_without_a_projection() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".cockpit")).unwrap();
        std::fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"prompt_injection_guard":{"threshold":"low"}}"#,
        )
        .unwrap();
        let tools = ToolBox::new().with(Arc::new(BashArtifactCaptureTool));
        let mut agent = test_agent(tools.clone());
        agent.scan_tool_results = true;
        let session = test_session(tmp.path());
        // Full-capture rechecking is deliberately bypassed in Yolo mode. Use
        // the normal approval posture so an unavailable recheck exercises the
        // fail-closed capture path below.
        session.set_approval_mode(ApprovalMode::Manual);
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("bash", serde_json::json!({ "command": "synthetic" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(
            policy,
            execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None),
        )
        .await
        .unwrap();

        let capped = "head line\n... [truncated]\ntail line\n";
        assert_eq!(last_tool_result_text(&history), capped);
        assert!(
            session
                .db
                .list_text_artifacts(session.id)
                .await
                .unwrap()
                .is_empty()
        );
        let session_id = session.id;
        let (refs, reservations): (i64, i64) = session
            .db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_text_artifact_event_refs WHERE session_id=?1",
                        [session_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_text_artifact_quota_reservations WHERE session_id=?1",
                        [session_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((refs, reservations), (0, 0));
        let events = session.db.list_session_events(session.id).await.unwrap();
        let event = events
            .iter()
            .find(|event| event.kind == "tool_call")
            .unwrap();
        assert!(event.data.get("artifact_projection").is_none());
        assert!(
            !event
                .data
                .to_string()
                .contains("INJECTION_SENTINEL_ONLY_IN_RETAINED_TAIL")
        );
        let resumed = crate::engine::rehydrate::rehydrate_session(&session.db, session.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(last_tool_result_text(&resumed.history), capped);
    }

    #[tokio::test]
    async fn recall_artifact_pseudofile_is_bounded_and_session_scoped() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let long_line = "é".repeat(5_000);
        let artifact = seed_tool_artifact(
            &session,
            &format!("first line\n{long_line}\nneedle+literal\nregex-42\n"),
            "recall-artifact-read-search",
        )
        .await;
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let path = format!(
            "cockpit://session/{}/artifacts/{}",
            session.short_id(),
            artifact.artifact_id
        );

        let first_page = crate::tools::recall::read(
            &serde_json::json!({ "path": path, "start_line": 2, "end_line": 2 }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(first_page.truncated);
        assert!(first_page.content.len() <= crate::tools::common::OUTPUT_BYTE_CAP);
        assert!(
            first_page
                .content
                .contains("start_line=2, end_line=2, start_byte=")
        );

        let literal = crate::tools::recall::grep(
            &serde_json::json!({ "path": path, "pattern": "needle+literal", "mode": "literal" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(literal.content.contains("needle+literal"));

        let regex = crate::tools::recall::grep(
            &serde_json::json!({ "path": path, "pattern": "regex-\\d+", "mode": "regex" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(regex.content.contains("regex-42"));

        let foreign = Arc::new(
            Session::create_for_test(
                session.db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let foreign_ctx = tool_ctx(foreign, tmp.path(), &tx);
        let hidden = crate::tools::recall::read(&serde_json::json!({ "path": path }), &foreign_ctx)
            .await
            .unwrap();
        assert!(hidden.content.contains("No readable artifact exists"));
    }

    #[tokio::test]
    async fn artifact_tools_recheck_imported_falsely_redacted_content_before_output() {
        let tmp = tempfile::tempdir().unwrap();
        let source_session = test_session(tmp.path());
        let secret = "super-secret-token-value";
        seed_tool_artifact(
            &source_session,
            &format!("safe line\n{secret}\n"),
            "artifact-imported-false-redaction",
        )
        .await;
        let source_row = source_session
            .db
            .get_session(source_session.id)
            .await
            .unwrap()
            .unwrap();
        // This test export has no matching source redactor, so the manifest's
        // redacted-length-preserving representation is structurally valid but
        // falsely claims this local secret was already removed.
        let archive = crate::session::export::build_zip(
            &source_session.db,
            &source_row,
            std::slice::from_ref(&source_row),
        )
        .await
        .unwrap();
        let imported_db = crate::db::Db::open_in_memory().unwrap();
        let imported = crate::session::import::import_archive(
            &imported_db,
            crate::session::import::read_archive_bytes(&archive).unwrap(),
        )
        .await
        .unwrap();
        let imported_session = Arc::new(
            Session::resume_for_test(
                imported_db,
                imported.imported[0],
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap()
            .unwrap(),
        );
        let artifact = imported_session
            .db
            .list_text_artifacts(imported_session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            artifact.representation,
            crate::db::text_artifacts::TextArtifactRepresentation::ExportRedacted
        );

        let (tx, _rx) = mpsc::channel(8);
        let mut ctx = tool_ctx(imported_session, tmp.path(), &tx);
        ctx.redact = Arc::new(redaction_table(tmp.path(), "[redacted]"));
        let path = format!(
            "cockpit://session/{}/artifacts/{}",
            ctx.session.short_id(),
            artifact.artifact_id
        );
        let read = crate::tools::recall::read(&serde_json::json!({ "path": path }), &ctx)
            .await
            .unwrap();
        assert!(!read.content.contains(secret));
        assert!(read.content.contains("[redacted]"));
        let search = crate::tools::recall::grep(
            &serde_json::json!({ "path": path, "pattern": secret, "mode": "literal" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(search.content, "No matches.");
    }

    async fn assert_named_artifact_is_readable(tool_name: &'static str) {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(NamedArtifactCaptureTool { name: tool_name }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(tool_name, serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, tool_name, Recovery::Clean, None)
            .await
            .unwrap();

        let artifact = session
            .db
            .list_text_artifacts(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let retrieved = crate::tools::recall::read(
            &serde_json::json!({
                "path": format!(
                    "cockpit://session/{}/artifacts/{}",
                    session.short_id(),
                    artifact.artifact_id
                )
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert!(retrieved.content.starts_with("1|head line\n"));
        assert!(retrieved.content.len() > "head line\n... [truncated]\ntail line\n".len());
    }

    #[tokio::test]
    async fn mcp_tool_artifact_is_readable() {
        assert_named_artifact_is_readable("mcp").await;
    }

    #[tokio::test]
    async fn custom_tool_artifact_is_readable() {
        assert_named_artifact_is_readable("custom_large").await;
    }

    #[tokio::test]
    async fn host_dropped_artifact_preserves_accounting() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(PartialArtifactCaptureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("big_partial", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(
            &env,
            &mut history,
            &call,
            "big_partial",
            Recovery::Clean,
            None,
        )
        .await
        .unwrap();

        let wire = last_tool_result_text(&history);
        assert!(wire.contains("\"host_original_bytes\":10000"), "{wire}");
        let stored = session.db.list_text_artifacts(session.id).await.unwrap();
        assert_eq!(stored[0].host_original_bytes, 10_000);
        assert!(stored[0].host_dropped_bytes > 0);
    }

    #[tokio::test]
    async fn artifact_frames_are_absent_without_a_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(TruncatedTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call("big", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "big", Recovery::Clean, None)
            .await
            .unwrap();

        let wire = last_tool_result_text(&history);
        assert!(!wire.contains("cockpit_artifact_v1"), "{wire}");
    }

    #[tokio::test]
    async fn recheck_modified_output_is_not_capture_eligible() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db,
            std::path::PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let delivered = "[tool result withheld]".to_string();
        let capture = crate::engine::tool::TextArtifactCapture {
            content: "raw content removed by recheck".to_string(),
            host_captured_bytes: "raw content removed by recheck".len(),
            host_original_bytes: "raw content removed by recheck".len(),
            host_dropped_bytes: 0,
            stored_source_bytes: "raw content removed by recheck".len(),
        };

        assert!(!text_artifact_capture_is_persistable(
            "code",
            Some(&capture),
            &delivered,
            true,
        ));
        assert!(
            session
                .db
                .list_text_artifacts(session.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
