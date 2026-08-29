use super::credentials_rejected_rebuild;
use super::*;

/// Maximum models attempted for one logical turn, including the primary.
///
/// The cap is deliberately small: failover is for provider/model outages, not
/// for scanning the entire catalog while a parent model keeps issuing work.
pub const MAX_FAILOVER_CANDIDATES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailoverAttempt {
    pub provider: String,
    pub model: String,
    pub error_class: Option<crate::engine::model::InferenceErrorClass>,
    pub outcome: &'static str,
}

impl FailoverAttempt {
    pub fn failed(model: &Model, error_class: &crate::engine::model::InferenceErrorClass) -> Self {
        Self {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
            error_class: Some(error_class.clone()),
            outcome: "failed",
        }
    }

    pub fn succeeded(model: &Model) -> Self {
        Self {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
            error_class: None,
            outcome: "succeeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFallbackDecision {
    pub primary_model: String,
    pub error_class: crate::engine::model::InferenceErrorClass,
    pub backup_model: String,
    pub fallback_tried: Vec<FailoverAttempt>,
}

impl BackupFallbackDecision {
    pub fn routing_value(&self) -> &'static str {
        "backup"
    }
}

pub fn suggested_action_for_failure_class(
    class: &crate::engine::model::InferenceErrorClass,
) -> &'static str {
    match class {
        crate::engine::model::InferenceErrorClass::TimeoutTtft
        | crate::engine::model::InferenceErrorClass::TimeoutIdle
        | crate::engine::model::InferenceErrorClass::Network => "retry_or_choose_another_model",
        crate::engine::model::InferenceErrorClass::MissingToolEntitlement { .. }
        | crate::engine::model::InferenceErrorClass::ClientSideToolsUnsupported => {
            "change_model_or_disable_tool"
        }
        crate::engine::model::InferenceErrorClass::Http(status) if (500..=599).contains(status) => {
            "retry_later_or_choose_another_model"
        }
        crate::engine::model::InferenceErrorClass::Http(status) if (400..=499).contains(status) => {
            "check_configuration_or_credentials"
        }
        // Billing/account-quota exhaustion: the same provider's account is out of
        // balance/quota, so the actionable recovery is to top up or switch
        // provider — never to retry the same model.
        crate::engine::model::InferenceErrorClass::BillingOrQuotaExhausted => {
            "top_up_balance_or_switch_provider"
        }
        crate::engine::model::InferenceErrorClass::UtilityTimeout
        | crate::engine::model::InferenceErrorClass::ResponsesToolIdentity
        | crate::engine::model::InferenceErrorClass::ProviderNotConfigured
        | crate::engine::model::InferenceErrorClass::ProviderRateLimit
        | crate::engine::model::InferenceErrorClass::UnrenderableWireField
        | crate::engine::model::InferenceErrorClass::Http(_)
        | crate::engine::model::InferenceErrorClass::Other(_) => "inspect_failure",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupTurnMetadata {
    pub fallback_decision: Option<BackupFallbackDecision>,
    pub fallback_tried: Vec<FailoverAttempt>,
}

/// Run one turn with per-turn primary-first backup-model fallback
/// (implementation note).
///
/// This is the single seam both the interactive driver loop and the
/// noninteractive subagent loop run their turns through, so **every** agent —
/// the primary, `builder`, `explore`, `docs`, `Swarm` — inherits the same
/// mechanism (subagents inherit it for free; nothing is hard-coded per agent).
///
/// Behavior:
/// - Always tries the **primary** model (`&agent.model`) first. Fallback does
///   not stick — the next call (next turn) tries the primary again.
/// - On a qualifying terminal [`InferenceFailure`]
///   ([`failure_engages_backup`]) **and** a configured `backup` model, retries
///   the *same* turn on the backup. The primary's red inline error is
///   suppressed (the primary attempt ran with `emit_inference_error_ui =
///   false`); instead a display-only yellow [`TurnEvent::BackupUsed`] banner is
///   emitted, then the backup attempt runs with `emit_inference_error_ui =
///   true` so that if the **backup also fails** the user sees the standard red
///   inline error (no second banner).
/// - On a *non*-qualifying failure (e.g. `http_400`), or when no backup is
///   configured, the failure is final: the red inline error is emitted and the
///   error is returned. (Because the primary attempt suppressed its own UI when
///   a backup *might* run, this path re-emits it from here.)
///
/// The banner is **display-only**: it rides the `TurnEvent`/proto/UI plumbing
/// (never the model's history), preserving the wire-vs-user split (GOALS §14).
#[allow(clippy::too_many_arguments)]
pub async fn turn_with_backup(
    agent: &Agent,
    backup_model: Option<&Arc<Model>>,
    fallback_models: &[Arc<Model>],
    history: &mut Vec<Message>,
    prompt: Message,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    is_root: bool,
    skill_write_origin: crate::skills::manage::SkillWriteOrigin,
    review_cage: Option<crate::engine::tool::ReviewCage>,
    context_usage: crate::engine::tool::ContextUsageSnapshot,
    deferred_log: crate::engine::deferred::DeferredLog,
    // Per-round-trip logical id generated by the driver and shared with the
    // primary tandem records. All attempts of this call share it; the immutable
    // per-attempt inference log distinguishes them by ordinal (primary 0, each
    // failover +1) so a terminal primary record cannot absorb the backup's
    // request body and the attempts stay correlated to one logical call.
    call_id: Uuid,
    // Model-comparison tandem (shadow) set — applied on the PRIMARY attempt
    // only (the backup retry passes `None`, so a fallback never double-shadows
    // the same logical call). implementation note.
    tandem: Option<&crate::engine::schedule::TandemSet>,
    goal_provenance: Option<(Uuid, i64)>,
    turn_id: Option<String>,
    tx: &mpsc::Sender<TurnEvent>,
    mut turn_metadata: Option<&mut BackupTurnMetadata>,
) -> Result<TurnOutcome> {
    let mut candidates: Vec<&Arc<Model>> = Vec::with_capacity(1 + fallback_models.len());
    if let Some(backup) = backup_model {
        candidates.push(backup);
    }
    for model in fallback_models {
        if candidates.len() + 1 >= MAX_FAILOVER_CANDIDATES {
            break;
        }
        let duplicate = candidates.iter().any(|candidate| {
            candidate.provider_id() == model.provider_id()
                && candidate.model_id_ref() == model.model_id_ref()
        });
        if !duplicate {
            candidates.push(model);
        }
    }

    // A trusted primary whose only candidates were untrusted has no failover
    // *because custody refused it*, not because none was configured. Compute it
    // up front: when it applies we must suppress `turn`'s own failure UI and
    // emit the augmented event ourselves, otherwise the reason never reaches
    // the user on either channel.
    let custody_block = if candidates.is_empty() {
        crate::engine::driver::failover_custody_block(&config.providers(), &agent.model)
    } else {
        None
    };

    let mut fallback_tried = Vec::new();
    let mut first_failure: Option<(String, crate::engine::model::InferenceErrorClass)> = None;
    // Failover state (issue #23). `current` is None for the primary and `Some(i)`
    // for candidate `i`; `tried` records dispatched candidate indices so the
    // recovery-aware selector never repeats one. `strategy` is fixed by the FIRST
    // (primary) failure's recovery signal and governs every subsequent candidate
    // choice; `billing_backup_used` enforces the single-different-provider-backup
    // cap for billing.
    let primary_provider = agent.model.provider_id().to_string();
    let candidate_providers: Vec<&str> = candidates.iter().map(|c| c.provider_id()).collect();
    let mut current: Option<usize> = None;
    let mut tried: Vec<usize> = Vec::new();
    let mut strategy = crate::engine::model::ProviderRecoverySignal::None;
    let mut strategy_set = false;
    let mut billing_backup_used = false;
    let mut attempt_ordinal = 0i64;
    // The primary attempt suppresses its own red inline error whenever a backup
    // MIGHT run (any candidate configured) or a custody block must append its
    // reason; the terminal branch below re-emits exactly once when advancement
    // finally stops. Only a no-candidate, no-custody primary emits its UI
    // directly. Loop-invariant by construction.
    let emit_failure_ui = candidates.is_empty() && custody_block.is_none();
    // One display lifetime spans every physical primary/failover dispatch in
    // this logical call. A failed visible stream stays open until either the
    // next attempt emits Reset or this wrapper proves failure is terminal.
    let display_slot =
        crate::engine::agent::turn_phases::new_display_attempt_slot(&session, &config);
    // Credentials-rejected rebuild-and-retry latch (AC5), scoped to the WHOLE
    // logical dispatch — declared OUTSIDE the failover loop so at most ONE
    // automatic command-secret rebuild-and-retry happens across every physical
    // attempt (primary + each failover candidate). A success returns out of the
    // function, so a later independent dispatch starts with a fresh latch.
    let mut credentials_rebuild_used = false;
    loop {
        let current_model: &Model = match current {
            None => &agent.model,
            Some(i) => candidates[i].as_ref(),
        };
        // Every dispatched target renders ITS OWN effective posture AND its own
        // model-specific system context. The primary (attempt 0) already carries
        // both; each failover/backup candidate is a DIFFERENT model, so re-render
        // this child's model-dependent surface (model-specific composed system +
        // role body + tool schemas/descriptions + tool steering) for the
        // candidate before the turn. The toolbox (and any grants) is preserved
        // intact — only its rendering switches.
        let repostured: Option<Agent> = if let Some(i) = current {
            let candidate_arc: &Arc<Model> = candidates[i];
            match crate::engine::builtin::reposture_agent_for_candidate(
                agent,
                candidate_arc,
                &session,
                &cwd,
                &session.db,
            )
            .await
            {
                Ok(reposed) => reposed,
                // Fail CLOSED: the candidate's own posture cannot be rendered, so
                // this failover candidate is NEVER dispatched under the primary's
                // posture. The def is the same for every candidate, so no later
                // candidate could re-render either — abort the whole failover with
                // the content-safe error (nothing was dispatched for this
                // candidate).
                Err(err) => return Err(err),
            }
        } else {
            None
        };
        let dispatch_agent: &Agent = repostured.as_ref().unwrap_or(agent);
        // Every attempt of one logical call SHARES the `call_id` and takes the
        // next ordinal (primary 0, each failover +1), so the immutable
        // per-attempt inference log keeps them as distinct `(call_id, ordinal)`
        // rows that are still correlatable to one logical call. (This reverts
        // the fresh-`Uuid::new_v4()`-per-attempt workaround, which decorrelated
        // failover attempts from their primary.)
        // Credentials-rejected rebuild-and-retry (AC5). On a provider auth
        // failure classified `CredentialsRejected` (401/403) for THIS target, if
        // the failing provider has an owner-scoped command-backed secret,
        // re-resolve ONLY that provider's secret(s), rebuild a FRESH model client
        // under a REFRESHED redaction table so the new token is scrubbed, and
        // retry the SAME target ONCE. The `credentials_rebuild_used` latch (above
        // the failover loop) permits at most ONE such rebuild across the whole
        // logical dispatch. A provider with no command-backed secret is NOT
        // rebuilt-and-retried (its original auth error surfaces immediately).
        // `CredentialsRejected` does not engage backup failover, so this runs
        // before the failover selection below.
        let mut rebuilt_model: Option<Arc<Model>> = None;
        let mut rebuilt_redact: Option<Arc<RedactionTable>> = None;
        let attempt_result = loop {
            let is_credentials_retry = rebuilt_model.is_some();
            let model_for_attempt: &Model = rebuilt_model.as_deref().unwrap_or(current_model);
            // The retry dispatches under the refreshed redaction table so the
            // freshly-resolved token is scrubbed on the recorded request too.
            let redact_for_attempt: &Arc<RedactionTable> =
                rebuilt_redact.as_ref().unwrap_or(&redact);
            let result = turn(
                dispatch_agent,
                model_for_attempt,
                history,
                prompt.clone(),
                session.clone(),
                locks.clone(),
                redact_for_attempt.clone(),
                cwd.clone(),
                config.clone(),
                interrupts.clone(),
                cancel.clone(),
                approver.clone(),
                lsp.clone(),
                resource_scheduler.clone(),
                loop_guard_threshold,
                is_root,
                skill_write_origin,
                review_cage.clone(),
                context_usage,
                deferred_log.clone(),
                emit_failure_ui,
                call_id,
                attempt_ordinal,
                // Tandem shadowing is a PRIMARY, first-attempt concern; a
                // credentials rebuild-retry must not re-shadow the same call.
                if current.is_none() && !is_credentials_retry {
                    tandem
                } else {
                    None
                },
                goal_provenance,
                turn_id.clone(),
                tx,
                Some(display_slot.clone()),
            )
            .await;

            // Copy the decision out with no borrow of `result` held.
            let attempt_rebuild = credentials_rejected_rebuild::should_attempt_credentials_rebuild(
                credentials_rejected_rebuild::result_is_credentials_rejected(&result),
                credentials_rebuild_used,
            );
            if !attempt_rebuild {
                break result;
            }
            match credentials_rejected_rebuild::rebuild_model_for_credentials(
                &session,
                &config,
                &redact,
                &dispatch_agent.env_overlay,
                model_for_attempt,
            )
            .await
            {
                Ok(Some(rebuilt)) => {
                    // A command-backed secret was re-resolved and a fresh client
                    // built: spend the latch and retry the same target once. The
                    // retry is a DISTINCT physical dispatch of the same logical
                    // call, so advance the ordinal to avoid colliding with the
                    // rejected attempt's `(call_id, ordinal)` inference-request
                    // row.
                    credentials_rebuild_used = true;
                    rebuilt_model = Some(Arc::new(rebuilt.model));
                    rebuilt_redact = Some(rebuilt.redact);
                    attempt_ordinal += 1;
                }
                Ok(None) => {
                    // Provider has no command-backed secret: not eligible. No
                    // exec, no rebuild, no retry — surface the original auth
                    // error unchanged.
                    break result;
                }
                Err(rebuild_err) => {
                    // Rebuild failed (unconfigured provider / bad id / store
                    // error): surface the ORIGINAL auth failure and take no
                    // further retry.
                    tracing::warn!(
                        %rebuild_err,
                        provider = %current_model.provider_id(),
                        model = %current_model.model_id_ref(),
                        "credentials rebuild failed; surfacing original auth error"
                    );
                    break result;
                }
            }
        };

        match attempt_result {
            Ok(outcome) => {
                if current.is_some() {
                    fallback_tried.push(FailoverAttempt::succeeded(current_model));
                    if let Some(metadata) = turn_metadata.as_deref_mut() {
                        metadata.fallback_tried = fallback_tried.clone();
                        if let Some((primary_model, error_class)) = first_failure {
                            metadata.fallback_decision = Some(BackupFallbackDecision {
                                primary_model,
                                error_class,
                                backup_model: current_model.model_id_ref().to_string(),
                                fallback_tried,
                            });
                        }
                    }
                }
                return Ok(outcome);
            }
            Err(err) => {
                let Some(failure) = crate::engine::model::as_inference_failure(&err) else {
                    return Err(err);
                };
                let class = failure.class.clone();
                fallback_tried.push(FailoverAttempt::failed(current_model, &class));
                if first_failure.is_none() {
                    first_failure = Some((failure.model.clone(), class.clone()));
                }
                // The failover STRATEGY is fixed by the first (primary) failure's
                // recovery signal (issue #23): billing routes to exactly one
                // different-provider backup; overload prefers a different provider;
                // an ordinary failure keeps the configured order.
                if !strategy_set {
                    strategy = failure.recovery;
                    strategy_set = true;
                }
                if let Some(i) = current {
                    tried.push(i);
                }
                let next = if crate::engine::model::failure_engages_backup(&class) {
                    select_next_backup_candidate(
                        &candidate_providers,
                        &tried,
                        &primary_provider,
                        strategy,
                        billing_backup_used,
                    )
                } else {
                    None
                };
                if next.is_none() {
                    // The block only explains a failure that *would* have
                    // engaged failover; an unrelated hard error keeps its own
                    // message.
                    let applied_block = custody_block
                        .as_ref()
                        .filter(|_| crate::engine::model::failure_engages_backup(&class));
                    let display_error_emitted = display_slot
                        .finish_as_error(
                            &agent.name,
                            crate::engine::response_performance::DisplayErrorKind::Failed,
                            class.as_str(),
                            Some(tx),
                        )
                        .await;
                    // The typed display error is the one and only UI row for
                    // a visible partial. Audit settlement above retains the
                    // failure/auth classification even when this live UI event
                    // is suppressed.
                    if !emit_failure_ui && !display_error_emitted {
                        // Route the raw provider detail through the omission
                        // funnel: the user-facing reason is the fixed marker
                        // (optionally prefixed to the advisory custody block),
                        // never the provider body.
                        let safe = crate::engine::model::safe_provider_detail(failure);
                        let detail = match applied_block {
                            Some(block) => {
                                format!("{}\n{}", safe.marker, block.user_message())
                            }
                            None => safe.marker_string(),
                        };
                        let _ = tx
                            .send(TurnEvent::InferenceFailed {
                                agent: agent.name.clone(),
                                provider: failure.provider.clone(),
                                model: failure.model.clone(),
                                error_class: failure.class.clone(),
                                detail,
                                auth_failure: crate::engine::model::auth_failure_kind(failure),
                            })
                            .await;
                    }
                    if let Some(metadata) = turn_metadata.as_deref_mut() {
                        metadata.fallback_tried = fallback_tried.clone();
                        if current.is_some()
                            && let Some((primary_model, error_class)) = first_failure
                        {
                            metadata.fallback_decision = Some(BackupFallbackDecision {
                                primary_model,
                                error_class,
                                backup_model: current_model.model_id_ref().to_string(),
                                fallback_tried,
                            });
                        }
                    }
                    return match applied_block {
                        // Keep the original `InferenceFailure` in the chain (the
                        // driver still downcasts to it) and add the typed
                        // custody reason as context for log/report surfaces.
                        // The user-visible channel is the event above.
                        Some(block) => Err(err.context(block.user_message())),
                        None => Err(err),
                    };
                }

                let next_idx = next.expect("next is Some in the advance branch");
                let next_model = candidates[next_idx].as_ref();
                let _ = tx
                    .send(TurnEvent::BackupUsed {
                        agent: agent.name.clone(),
                        primary_model: failure.model.clone(),
                        error_class: class,
                        backup_model: next_model.model_id_ref().to_string(),
                    })
                    .await;
                // A billing failover consumes its single allowed different-provider
                // backup; a second billing failure then has no candidate and is
                // terminal.
                if strategy == crate::engine::model::ProviderRecoverySignal::BillingExhausted {
                    billing_backup_used = true;
                }
                current = Some(next_idx);
                attempt_ordinal += 1;
            }
        }
    }
}

/// Select the next backup candidate index given the failover `strategy` fixed by
/// the FIRST (primary) failure and the `primary_provider` we route away from.
/// `candidate_providers[i]` is candidate `i`'s provider id. Billing tries exactly
/// one different-provider candidate; overload prefers a different provider,
/// falling back to a same-provider one only when no different-provider candidate
/// remains; an ordinary failure keeps the configured order. Returns `None` when
/// no eligible candidate is left.
pub(crate) fn select_next_backup_candidate(
    candidate_providers: &[&str],
    tried: &[usize],
    primary_provider: &str,
    strategy: crate::engine::model::ProviderRecoverySignal,
    billing_backup_used: bool,
) -> Option<usize> {
    let untried = |i: &usize| !tried.contains(i);
    let different_provider = |i: &usize| candidate_providers[*i] != primary_provider;
    match strategy {
        crate::engine::model::ProviderRecoverySignal::BillingExhausted => {
            if billing_backup_used {
                None
            } else {
                (0..candidate_providers.len()).find(|i| untried(i) && different_provider(i))
            }
        }
        crate::engine::model::ProviderRecoverySignal::Overloaded => (0..candidate_providers.len())
            .find(|i| untried(i) && different_provider(i))
            .or_else(|| (0..candidate_providers.len()).find(|i| untried(i))),
        crate::engine::model::ProviderRecoverySignal::None => {
            (0..candidate_providers.len()).find(|i| untried(i))
        }
    }
}

/// Settle the dispatch-time inference record to its terminal status and
/// surface the failure (`inference-timeout-and-failure-
/// observability.md` #2/#3/#4). For a well-typed [`InferenceFailure`] (a
/// timeout / network / non-retryable HTTP error): record the terminal status
/// (`timed_out` for either timeout class, else `errored`), append an
/// `inference_failure` event carrying provider/model/phase/class/elapsed, and
/// emit the red inline `InferenceFailed` event. A clean cancel / drain unwind
/// (the `InferenceCancelled` / `InferenceGated` sentinels) records its
/// terminal status only (`cancelled`) — no red error, no failure event (the
/// driver unwinds those silently). All writes are best-effort.
pub(crate) struct InferenceOutcomeRecord<'a> {
    pub(crate) session: Arc<Session>,
    pub(crate) call_id: Uuid,
    /// Dispatched-target attempt index of the row to settle. The immutable body
    /// was already inserted at dispatch under `(call_id, ordinal)`; settle only
    /// advances that row's status + phase columns, never its body.
    pub(crate) ordinal: i64,
    pub(crate) agent_name: &'a str,
    pub(crate) wire_api: &'a str,
    pub(crate) routing_metadata: Value,
    pub(crate) emit_inference_error_ui: bool,
    pub(crate) goal_provenance: Option<(Uuid, i64)>,
    pub(crate) tx: &'a mpsc::Sender<TurnEvent>,
}

pub(crate) async fn record_inference_outcome(ctx: InferenceOutcomeRecord<'_>, err: &anyhow::Error) {
    use crate::db::session_log::{InferencePhaseTimings, InferenceRequestStatus, SessionEventKind};
    use crate::engine::model::as_inference_failure;

    let InferenceOutcomeRecord {
        session,
        call_id,
        ordinal,
        agent_name,
        wire_api,
        routing_metadata,
        emit_inference_error_ui,
        goal_provenance,
        tx,
    } = ctx;
    // Goal provenance is stamped on the row at body-insert time; the terminal
    // settle only advances status + phase columns.
    let _ = goal_provenance;

    // A user cancel or daemon-drain unwind: record `cancelled` and return —
    // the driver handles these silently (no red error to the user).
    if crate::engine::model::is_cancelled(err) || crate::engine::model::is_gated(err) {
        if session
            .advance_inference_request(
                call_id,
                ordinal,
                InferenceRequestStatus::Cancelled,
                InferencePhaseTimings::default(),
            )
            .await
            .is_err()
        {
            tracing::warn!("primary inference audit cancellation write failed");
        }
        return;
    }

    let Some(failure) = as_inference_failure(err) else {
        // An unexpected error shape (not the typed seam) — still settle the
        // record to `errored` so the export isn't left at `pending`.
        if session
            .advance_inference_request(
                call_id,
                ordinal,
                InferenceRequestStatus::Errored,
                InferencePhaseTimings::default(),
            )
            .await
            .is_err()
        {
            tracing::warn!("primary inference audit error write failed");
        }
        return;
    };

    let status = if failure.class.is_timeout() {
        InferenceRequestStatus::TimedOut
    } else {
        InferenceRequestStatus::Errored
    };
    if session
        .advance_inference_request(
            call_id,
            ordinal,
            status,
            InferencePhaseTimings {
                failed_ms: Some(failure.elapsed_ms as i64),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .is_err()
    {
        tracing::warn!("primary inference audit failure write failed");
    }

    let diagnostics = inference_failure_diagnostics(failure, wire_api);

    // Failure event (Part B): lands in the export's events.json, keyed by this
    // attempt's call_id. Data/export only — never enters model context.
    //
    // Host/provider-authored, not model-authored: every field is failure
    // telemetry the host computed or the provider returned (provider status /
    // body snippet, host classification rationale, recommended action, timings).
    // The session model produced no output on this failed attempt, so this payload
    // carries no model-authored session-table literal. Frame-less `record_event`
    // is correct; nothing to journal.
    if session
        .record_event(
            SessionEventKind::InferenceFailure,
            Some(agent_name),
            Some(&call_id.to_string()),
            &serde_json::json!({
                "provider": failure.provider,
                "model": failure.model,
                "wire_api": wire_api,
                "routing": routing_metadata,
                "phase_reached": failure.phase,
                "error_class": failure.class,
                "elapsed_ms": failure.elapsed_ms,
                // Raw provider detail is omitted on the audit channel too; the
                // funnel's fixed marker stands in for both the `detail` and the
                // `provider_body_snippet` free-text fields.
                "detail": crate::engine::model::PROVIDER_DETAIL_OMITTED,
                "provider_status": diagnostics.provider_status,
                "provider_body_snippet": diagnostics.provider_body_snippet,
                "recovery": diagnostics.recovery,
                "retry_attempts": diagnostics.retry_attempts,
                "retry_final_decision": diagnostics.retry_final_decision,
                "classification_rationale": diagnostics.classification_rationale,
                "recommended_action": diagnostics.recommended_action,
                // Correlate this failure event to the attempt's immutable
                // `(call_id, ordinal)` inference-request row for export.
                "ordinal": ordinal,
            }),
        )
        .await
        .is_err()
    {
        tracing::warn!("inference failure audit event write failed");
    }

    // Red inline error for the user (same treatment as a ToolError). UI-only.
    // Suppressed for the *primary* attempt under the per-turn backup wrapper
    // (implementation note): the wrapper shows a yellow
    // banner on backup success instead, and emits the red error itself only
    // when there is no qualifying fallback. The DB record + failure event
    // above are written either way (data-side is unconditional).
    if emit_inference_error_ui {
        let _ = tx
            .send(TurnEvent::InferenceFailed {
                agent: agent_name.to_string(),
                provider: failure.provider.clone(),
                model: failure.model.clone(),
                error_class: failure.class.clone(),
                // Raw provider detail is omitted; the red inline error shows the
                // fixed marker (the typed `error_class` carries the real class).
                detail: crate::engine::model::safe_provider_detail(failure).marker_string(),
                auth_failure: crate::engine::model::auth_failure_kind(failure),
            })
            .await;
    }
}

/// Narrow cross-module test seam for export regressions. Keeps the production
/// failure-event builder as the sole path under test without exposing its
/// per-turn UI plumbing outside this module.
#[cfg(test)]
pub(crate) async fn record_inference_outcome_for_export_test(
    session: Arc<Session>,
    call_id: Uuid,
    ordinal: i64,
    err: &anyhow::Error,
) {
    let (tx, _rx) = mpsc::channel(1);
    record_inference_outcome(
        InferenceOutcomeRecord {
            session,
            call_id,
            ordinal,
            agent_name: "builder",
            wire_api: "responses",
            routing_metadata: serde_json::json!({}),
            emit_inference_error_ui: false,
            goal_provenance: None,
            tx: &tx,
        },
        err,
    )
    .await;
}

#[derive(Debug)]
struct InferenceFailureDiagnostics {
    provider_status: Option<u16>,
    provider_body_snippet: Option<String>,
    retry_attempts: serde_json::Value,
    retry_final_decision: &'static str,
    classification_rationale: &'static str,
    recommended_action: &'static str,
    /// Typed provider-recovery signal (queryable metadata that survives the
    /// raw-detail omission).
    recovery: &'static str,
}

fn inference_failure_diagnostics(
    failure: &crate::engine::model::InferenceFailure,
    _wire_api: &str,
) -> InferenceFailureDiagnostics {
    // The ROUTING/rationale decision stays class-based; the DIAGNOSTIC status
    // uses the retained observed status so a billing failure reclassified to
    // `BillingOrQuotaExhausted` still reports its observed 429 (issue #23, B4).
    let class_status = failure.class.provider_status();
    // Route the raw provider body through the omission funnel: the audit
    // record's diagnostic snippet is the fixed marker, never the provider text.
    // The observed status class and recovery kind remain queryable.
    let safe = crate::engine::model::safe_provider_detail(failure);
    let provider_body_snippet = Some(safe.marker_string());
    let (retry_final_decision, classification_rationale) =
        crate::engine::retry::failure_retry_decision_and_rationale(&failure.class, class_status);
    InferenceFailureDiagnostics {
        provider_status: safe.observed_status,
        provider_body_snippet,
        retry_attempts: serde_json::json!({
            "known": true,
            "attempts": failure.retry_attempts,
        }),
        retry_final_decision,
        classification_rationale,
        recommended_action: suggested_action_for_failure_class(&failure.class),
        recovery: safe.recovery.as_str(),
    }
}

#[cfg(test)]
mod inference_outcome_tests {
    //! Dispatch-time recording lifecycle (`inference-timeout-and-
    //! failure-observability.md`): a hung/failed turn settles its `pending`
    //! record to a terminal status, records a failure event, and surfaces a
    //! red inline error.
    use super::*;
    use crate::db::session_log::InferenceRequestStatus;
    use crate::engine::model::{InferenceErrorClass, InferenceFailure};

    fn in_memory_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db,
                root.to_path_buf(),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        // The durable-before-handoff barrier is non-optional; install a
        // production-shaped journal so backup/failover dispatch is exercised.
        session.install_test_external_journal();
        session
    }

    async fn emitted_auth_failure(
        class: InferenceErrorClass,
        detail: &str,
    ) -> Option<crate::daemon::proto::AuthFailureKind> {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "mock-model" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let err = anyhow::Error::new(InferenceFailure {
            provider: "mock-provider".into(),
            model: "mock-model".into(),
            phase: "dispatched".into(),
            class,
            elapsed_ms: 1,
            retry_attempts: 1,
            detail: detail.into(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        });
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(4);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session,
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;
        match rx.recv().await.expect("mocked failure event") {
            TurnEvent::InferenceFailed { auth_failure, .. } => auth_failure,
            event => panic!("expected inference failure, got {event:?}"),
        }
    }

    #[tokio::test]
    async fn auth_failure_classified_on_event() {
        assert_eq!(
            emitted_auth_failure(InferenceErrorClass::Http(401), "unauthorized").await,
            Some(crate::daemon::proto::AuthFailureKind::CredentialsRejected { status: 401 })
        );
    }

    #[tokio::test]
    async fn rate_limit_not_auth_failure() {
        assert_eq!(
            emitted_auth_failure(InferenceErrorClass::Http(429), "too many requests").await,
            None
        );
    }

    #[tokio::test]
    async fn timeout_settles_pending_record_and_emits_red_error() {
        // Simulate the `turn()` flow on a hang: write the dispatch-time
        // `pending` record, then a TTFT-timeout `InferenceFailure` arrives.
        // The record must settle to `timed_out`, a failure event must be
        // recorded, and a red `InferenceFailed` event must be emitted.
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "qwen3", "system": "s", "history": [] });

        // Dispatch-time write (status pending) — exactly what `turn()` does
        // before the call.
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "pending", "the hung turn is frozen at pending");

        // The hang aborts with a TTFT timeout.
        let err = anyhow::Error::new(InferenceFailure {
            provider: "openai-compatible".into(),
            model: "qwen3".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::TimeoutTtft,
            elapsed_ms: 120_000,
            retry_attempts: 1,
            detail: String::new(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        })
        .context("completion call for agent `builder`");

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;

        // The record settled to `timed_out` (not left at pending).
        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "timed_out");

        // A failure event landed in the timeline carrying the diagnostics.
        let events = session.db.list_session_events(session.id).await.unwrap();
        let fail = events
            .iter()
            .find(|e| e.kind == "inference_failure")
            .expect("an inference_failure event was recorded");
        assert_eq!(fail.data["error_class"], serde_json::json!("timeout_ttft"));
        assert_eq!(fail.data["phase_reached"], "dispatched");
        assert_eq!(fail.data["elapsed_ms"], 120_000);
        assert_eq!(fail.data["provider"], "openai-compatible");
        assert_eq!(fail.data["model"], "qwen3");
        assert_eq!(fail.data["wire_api"], "responses");
        assert_eq!(fail.data["retry_final_decision"], "fail_fast");
        assert_eq!(
            fail.data["classification_rationale"],
            "time_to_first_token_timeout"
        );
        assert_eq!(
            fail.data["recommended_action"],
            "retry_or_choose_another_model"
        );

        // The red inline error was emitted to the UI.
        let mut saw_red = false;
        while let Ok(ev) = rx.try_recv() {
            if let TurnEvent::InferenceFailed { error_class, .. } = ev {
                assert_eq!(error_class, InferenceErrorClass::TimeoutTtft);
                saw_red = true;
            }
        }
        assert!(saw_red, "a red InferenceFailed event must reach the UI");
    }

    #[test]
    fn recommended_action_is_derived_from_failure_class() {
        assert_ne!(
            suggested_action_for_failure_class(&InferenceErrorClass::TimeoutTtft),
            suggested_action_for_failure_class(&InferenceErrorClass::Http(400))
        );
        assert_ne!(
            suggested_action_for_failure_class(&InferenceErrorClass::Http(400)),
            "retry_same_turn"
        );
    }

    #[tokio::test]
    async fn inference_failure_reports_real_retry_attempts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "mock-model" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let err = anyhow::Error::new(InferenceFailure {
            provider: "mock-provider".into(),
            model: "mock-model".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::Network,
            elapsed_ms: 42,
            retry_attempts: 3,
            detail: "connection refused".into(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        });
        let (tx, _rx) = mpsc::channel::<TurnEvent>(4);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: false,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;
        let events = session.db.list_session_events(session.id).await.unwrap();
        let fail = events
            .iter()
            .find(|e| e.kind == "inference_failure")
            .expect("inference failure event");
        assert_eq!(fail.data["retry_attempts"]["known"], true);
        assert_eq!(fail.data["retry_attempts"]["attempts"], 3);
    }

    #[tokio::test]
    async fn detailed_provider_headers_stay_out_of_stored_and_emitted_failure_details() {
        const SENTINEL: &str = "RAW_INFERENCE_PROVIDER_HEADER_3d75_must_not_persist";
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        session
            .record_inference_request(
                call_id,
                &serde_json::json!({ "model": "mock-model" }),
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();

        let mut headers = rig::http_client::HeaderMap::new();
        headers.insert(
            "x-flycockpit-sentinel",
            rig::http_client::HeaderValue::from_static(SENTINEL),
        );
        let raw = rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithDetails {
                status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                body: "insufficient balance".to_string(),
                headers: Box::new(headers),
            },
        );
        // Rig itself retains the header, proving this regression cannot pass by
        // merely using a fixture that never carried sensitive metadata.
        assert!(format!("{raw:?}").contains(SENTINEL));

        // This is the production dispatch conversion: it applies
        // `classify_terminal_failure_with_floor` and `failure_detail` before
        // `record_inference_outcome` sees the resulting typed failure.
        let failure = crate::engine::model::terminal_inference_failure(
            &raw,
            "mock-provider",
            "mock-model",
            crate::engine::model::InferencePhase::Dispatched,
            42,
            3,
            crate::engine::model::ProviderRecoverySignal::None,
        );
        assert_eq!(failure.class, InferenceErrorClass::BillingOrQuotaExhausted);
        assert_eq!(failure.observed_status, Some(429));
        assert_eq!(
            failure.recovery,
            crate::engine::model::ProviderRecoverySignal::BillingExhausted
        );

        let err = anyhow::Error::new(failure);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(4);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;

        let events = session.db.list_session_events(session.id).await.unwrap();
        let fail = events
            .iter()
            .find(|event| event.kind == "inference_failure")
            .expect("inference failure event");
        assert!(!fail.data.to_string().contains(SENTINEL));
        assert_eq!(
            fail.data["detail"],
            crate::engine::model::PROVIDER_DETAIL_OMITTED
        );
        assert_eq!(fail.data["provider_status"], 429);
        assert_eq!(fail.data["recovery"], "billing_exhausted");

        match rx.recv().await.expect("inference failed event") {
            TurnEvent::InferenceFailed {
                detail,
                error_class,
                ..
            } => {
                assert!(!detail.contains(SENTINEL));
                assert_eq!(detail, crate::engine::model::PROVIDER_DETAIL_OMITTED);
                assert_eq!(error_class, InferenceErrorClass::BillingOrQuotaExhausted);
            }
            event => panic!("expected inference failure, got {event:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_settles_record_cancelled_without_red_error_or_event() {
        // A ctrl+c unwind (InferenceCancelled sentinel) settles the record to
        // `cancelled` and emits NO red error and NO failure event — the driver
        // unwinds those silently.
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "m" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();

        let err = anyhow::Error::new(crate::engine::model::InferenceCancelled {
            phase: crate::engine::model::InferencePhase::Prep,
        });
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        // A cancel emits no UI regardless of the flag; pass `true` to prove it.
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;

        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "cancelled");
        // No failure event, no red error.
        let events = session.db.list_session_events(session.id).await.unwrap();
        assert!(!events.iter().any(|e| e.kind == "inference_failure"));
        assert!(rx.try_recv().is_err(), "no UI event on a clean cancel");
    }
}

/// End-to-end per-turn backup-model fallback tests
/// (implementation note). Each builds two real
/// `Model::OpenAi` endpoints against local TCP servers we control — one that
/// returns a terminal HTTP 500 and one that streams a valid one-token
/// chat-completions SSE response — and drives
/// [`turn_with_backup`] across them, asserting the primary-first behavior, the
/// yellow display-only banner, the backup-also-fails inline error, and that the
/// banner never enters model context.
#[cfg(test)]
mod backup_fallback_tests {
    use super::*;
    use crate::config::providers::{
        BackupConfig, ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig, TimeoutConfig,
    };
    use crate::engine::model::InferenceErrorClass;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A local server that returns a deterministic HTTP 500. Returns the bound
    /// `base_url` (`http://127.0.0.1:PORT/v1`).
    async fn failing_server() -> String {
        failing_server_with_status(500).await
    }

    async fn failing_server_with_status(status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let body = r#"{"error":{"message":"server failed"}}"#;
                    let resp = format!(
                        "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// A local server that, for every connection, reads the request and returns
    /// a minimal valid chat-completions SSE stream: one text delta = `body`,
    /// then a finish + `[DONE]`. Returns the bound `base_url`.
    async fn sse_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    // Drain the request headers (best-effort) before replying.
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let payload = format!(
                        "data: {{\"id\":\"c\",\"model\":\"m\",\"choices\":[{{\"delta\":{{\"content\":\"{body}\"}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
                         data: {{\"id\":\"c\",\"model\":\"m\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"total_tokens\":2}}}}\n\n\
                         data: [DONE]\n\n"
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// A stream that exposes a provisional body, then fails decoding its next
    /// SSE item. This deterministically exercises failover after visible output.
    async fn partial_then_stream_error_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let payload = format!(
                        "data: {{\"id\":\"c\",\"model\":\"m\",\"choices\":[{{\"delta\":{{\"content\":\"{body}\"}},\"finish_reason\":null}}],\"usage\":null}}\n\n"
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                    // A malformed HTTP chunk after the valid SSE event makes
                    // the body stream fail after exposing the provisional
                    // delta. Malformed SSE data is ignored by the client and
                    // therefore cannot exercise the terminal stream path.
                    let _ = stream.write_all(b"not-a-chunk-size\r\n").await;
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// A keyless OpenAI-compat provider config at `url`.
    fn provider_at(url: &str) -> ProviderEntry {
        ProviderEntry {
            url: url.to_string(),
            headers: vec![],
            timeout: TimeoutConfig {
                ttft_secs: 1,
                idle_secs: 1,
            },
            ..ProviderEntry::default()
        }
    }

    fn provider_with_model(url: &str, model: &str) -> ProviderEntry {
        ProviderEntry {
            models: vec![ModelEntry {
                id: model.to_string(),
                subagent_invokable: Some(true),
                ..ModelEntry::default()
            }],
            ..provider_at(url)
        }
    }

    /// Build a minimal `Agent` carrying `model` and no tools (so a text-only
    /// turn ends as `Done`).
    fn agent_with(model: Arc<Model>) -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "s".to_string(),
            role_prompt: "s".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: ModelParams::default(),
            scan_tool_results: true,
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
        }
    }

    fn in_memory_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db,
                root.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        // The durable-before-handoff barrier is non-optional; install a
        // production-shaped journal so backup/failover dispatch is exercised.
        session.install_test_external_journal();
        session
    }

    fn ctx() -> (
        tempfile::TempDir,
        Arc<Session>,
        Arc<crate::locks::LockManager>,
        Arc<RedactionTable>,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let redact = Arc::new(RedactionTable::empty());
        (tmp, session, locks, redact)
    }

    async fn run(
        agent: &Agent,
        backup: Option<&Arc<Model>>,
        session: Arc<Session>,
        locks: Arc<crate::locks::LockManager>,
        redact: Arc<RedactionTable>,
        cwd: std::path::PathBuf,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<TurnOutcome> {
        turn_with_backup(
            agent,
            backup,
            &[],
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            cwd,
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            tx,
            None,
        )
        .await
    }

    /// Drain currently-buffered events into a vec (the turn is over by now).
    fn drain(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    /// AC12 — through the production failover path, each attempt's wire body is
    /// redacted for ITS OWN target and the immutable per-attempt log keeps one
    /// row per attempt whose payload byte-matches that target's wire redaction
    /// state.
    ///
    /// DIRECTION INVERSION (deliberate deviation from the AC12 wording): the
    /// prompt names a trusted-primary→untrusted-failover scenario, but that
    /// scenario is IMPOSSIBLE on the real path. Failover custody is upgrade-only
    /// ([`FailoverCustody`] / `build_failover_models_with_diagnostics`): a
    /// trusted primary REFUSES every untrusted candidate rather than re-rendering
    /// its raw trusted body onto an untrusted wire. That rejection is itself the
    /// enforcement of the "no raw trusted body reused on an untrusted wire"
    /// invariant, and it is proven directly by
    /// [`trusted_primary_refuses_untrusted_failover_and_records_it`] and
    /// [`untrusted_failover_after_trusted_primary_is_rejected_by_custody`] below.
    /// So the direction the real path permits — and the one that exercises
    /// target-specific redaction with a mixed-trust pair — is inverted here to an
    /// untrusted primary failing over to a trusted failover: the untrusted
    /// primary's wire is redacted (no sentinel), the trusted failover's wire is
    /// raw (sentinel present), both derived from the same raw history snapshot,
    /// and each stored attempt payload byte-agrees with its own captured wire
    /// body's redaction state.
    #[tokio::test]
    async fn interactive_backup_and_failover_redaction_is_target_specific() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};
        use cockpit_test_support::provider::{ScriptedProvider, Turn, Usage};

        let sentinel = "SENTINEL-SECRET-abcdef012345";

        let primary_provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 500,
                body: "boom".into(),
            })
            // Serve 500 for any internal HTTP retries too, so the attempt
            // settles to a stable Http(500) failure that engages failover.
            .repeat_last()
            .start()
            .await;
        let backup_provider = ScriptedProvider::builder()
            .turn(Turn::Text("answered by trusted failover".into()))
            .with_usage(Usage {
                prompt_tokens: 3,
                completion_tokens: 4,
                total_tokens: 7,
                use_alias_names: false,
            })
            .start()
            .await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: primary_provider.base_url(),
                models: vec![ModelEntry {
                    id: "primary-model".into(),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "local".into(),
            ProviderEntry {
                url: backup_provider.base_url(),
                models: vec![ModelEntry {
                    id: "backup-model".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        // A session table that scrubs the sentinel; each Model resolves its own
        // effective table from its custody (untrusted enforces it, trusted
        // releases the raw empty table).
        let table = Arc::new(
            RedactionTable::empty()
                .with_forced_literal(sentinel.to_string(), "$test".to_string())
                .unwrap(),
        );
        let primary =
            Arc::new(Model::for_provider(&cfg, "cloud", "primary-model", table.clone()).unwrap());
        let backup =
            Arc::new(Model::for_provider(&cfg, "local", "backup-model", table.clone()).unwrap());
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let call_id = Uuid::new_v4();

        let outcome = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut Vec::new(),
            Message::user(format!("the deploy secret is {sentinel}")),
            session.clone(),
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            call_id,
            None,
            None,
            None,
            &tx,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TurnOutcome::Done));
        let _ = drain(&mut rx);

        // Per-target wire capture (real HTTP boundary): the untrusted primary's
        // body is redacted, the trusted failover's body is raw.
        let primary_body = serde_json::to_string(&primary_provider.captured()[0].body).unwrap();
        let backup_body = serde_json::to_string(&backup_provider.captured()[0].body).unwrap();
        assert!(
            !primary_body.contains(sentinel),
            "untrusted primary wire body is redacted: {primary_body}"
        );
        assert!(
            backup_body.contains(sentinel),
            "trusted failover wire body is raw: {backup_body}"
        );

        // Two immutable attempt rows under one call_id, whose stored payloads
        // byte-match their captured wire redaction state.
        let attempts = session
            .db
            .list_inference_requests_for_call(&call_id.to_string())
            .await
            .unwrap();
        assert_eq!(attempts.len(), 2, "primary + failover both retained");
        assert_eq!(attempts[0].ordinal, 0);
        assert_eq!(attempts[0].trust.as_deref(), Some("untrusted"));
        assert!(
            !serde_json::to_string(&attempts[0].payload)
                .unwrap()
                .contains(sentinel),
            "primary row payload is redacted"
        );
        assert_eq!(attempts[1].ordinal, 1);
        assert_eq!(attempts[1].trust.as_deref(), Some("trusted"));
        assert!(
            serde_json::to_string(&attempts[1].payload)
                .unwrap()
                .contains(sentinel),
            "failover row payload is raw"
        );

        // Byte-level redaction-state agreement: each stored `(call_id, ordinal)`
        // payload agrees with its OWN captured wire body on whether the sentinel
        // is present — so the audited body is the same redaction state that hit
        // that target's wire, per target.
        let primary_stored = serde_json::to_string(&attempts[0].payload).unwrap();
        let backup_stored = serde_json::to_string(&attempts[1].payload).unwrap();
        assert_eq!(
            primary_stored.contains(sentinel),
            primary_body.contains(sentinel),
            "primary stored payload byte-matches its wire body's redaction state"
        );
        assert_eq!(
            backup_stored.contains(sentinel),
            backup_body.contains(sentinel),
            "failover stored payload byte-matches its wire body's redaction state"
        );
    }

    /// Companion to [`interactive_backup_and_failover_redaction_is_target_specific`]:
    /// the direction that test cannot exercise (trusted primary →
    /// untrusted failover) is REJECTED by the custody gate. This is the positive
    /// enforcement of the "no raw trusted body is ever re-rendered onto an
    /// untrusted wire" invariant: the untrusted candidate is refused, so no wire
    /// body for it is ever produced. (A broader recording/user-visibility proof
    /// lives in `trusted_primary_refuses_untrusted_failover_and_records_it`.)
    #[test]
    fn untrusted_failover_after_trusted_primary_is_rejected_by_custody() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                backup: Some(BackupConfig {
                    provider: "cloud".into(),
                    model: "cloud-model".into(),
                }),
                models: vec![ModelEntry {
                    id: "trusted-primary".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "cloud-model".into(),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        let primary = Model::for_provider(
            &cfg,
            "local",
            "trusted-primary",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(primary.is_trusted());

        // The untrusted candidate is refused (custody upgrade-only), so failover
        // produces NO untrusted target — the trusted primary's raw body can never
        // be re-rendered onto an untrusted wire because there is no such wire.
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            fallbacks.is_empty(),
            "no untrusted failover target may exist after a trusted primary: {:?}",
            fallbacks
                .iter()
                .map(|m| format!("{}:{}", m.provider_id(), m.model_id_ref()))
                .collect::<Vec<_>>()
        );
        assert!(
            refusals
                .iter()
                .any(|r| r.provider == "cloud" && r.model == "cloud-model"),
            "the untrusted candidate is recorded as refused: {refusals:?}"
        );
        // And the custody block is a user-visible reason for the rejection.
        assert!(
            crate::engine::driver::failover_custody_block(&cfg, &primary).is_some(),
            "a trusted primary with only untrusted candidates is custody-blocked"
        );
    }

    /// Terminal primary failure → answered by the backup, with a display-only
    /// yellow `BackupUsed` banner and NO red `InferenceFailed` for the primary.
    #[tokio::test]
    async fn terminal_failure_falls_back_to_backup_with_yellow_banner() {
        let primary_url = failing_server().await;
        let backup_url = sse_server("from-backup").await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));

        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let outcome = run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("backup answers the turn");
        assert!(matches!(outcome, TurnOutcome::Done));

        let events = drain(&mut rx);
        // A yellow display-only banner naming primary failure + backup answer.
        let banner = events.iter().find_map(|e| match e {
            TurnEvent::BackupUsed {
                primary_model,
                error_class,
                backup_model,
                ..
            } => Some((
                primary_model.clone(),
                error_class.clone(),
                backup_model.clone(),
            )),
            _ => None,
        });
        let (pm, class, bm) = banner.expect("a BackupUsed banner was emitted");
        assert_eq!(pm, "primary-model");
        assert_eq!(class, InferenceErrorClass::Http(500));
        assert_eq!(bm, "backup-model");
        // The backup's text reached the UI.
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantText { text, .. } if text.contains("from-backup")
        )));
        // NO red inline error for the primary (it was suppressed).
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::InferenceFailed { .. })),
            "the primary's red error must be suppressed when the backup answers"
        );
    }

    #[tokio::test]
    async fn visible_primary_partial_resets_when_backup_begins() {
        let primary_url = partial_then_stream_error_server("primary-partial").await;
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);

        let outcome = run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("backup answers after visible primary failure");
        assert!(matches!(outcome, TurnOutcome::Done));

        let events = drain(&mut rx);
        let backup_delta = events
            .iter()
            .find_map(|event| match event {
                TurnEvent::AssistantDisplayTextDelta {
                    attempt_id, delta, ..
                } if delta == "from-backup" => Some(*attempt_id),
                _ => None,
            })
            .expect("backup typed delta");
        let reset = events
            .iter()
            .rev()
            .find_map(|event| match event {
                TurnEvent::AssistantDisplayAttemptReset {
                    failed_attempt_id,
                    replacement_attempt_id,
                    ..
                } if *replacement_attempt_id == backup_delta => {
                    Some((*failed_attempt_id, *replacement_attempt_id))
                }
                _ => None,
            })
            .expect("visible primary is reset by the backup attempt");
        assert_ne!(reset.0, reset.1);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, TurnEvent::AssistantDisplayError { .. })),
            "a replaced visible primary emits Reset, not Error"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, TurnEvent::InferenceFailed { .. })),
            "an answered failover emits no terminal inference row"
        );
    }

    #[tokio::test]
    async fn visible_terminal_failure_emits_exactly_one_display_error_row() {
        let primary_url = partial_then_stream_error_server("terminal-partial").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);

        let result = run(
            &agent,
            None,
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await;
        assert!(result.is_err(), "malformed stream is terminal");

        let events = drain(&mut rx);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TurnEvent::AssistantDisplayError { .. }))
                .count(),
            1,
            "visible terminal failure has one typed display error"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TurnEvent::InferenceFailed { .. }))
                .count(),
            0,
            "typed display error suppresses the duplicate inference row"
        );
    }

    #[tokio::test]
    async fn failover_walk_stops_at_candidate_cap() {
        let failing_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "flaky".into(),
            provider_with_model(&failing_url, "primary-model"),
        );
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let mut fallbacks = Vec::new();
        for idx in 0..(MAX_FAILOVER_CANDIDATES + 2) {
            let provider = format!("dead-{idx}");
            cfg.providers.insert(
                provider.clone(),
                provider_with_model(&failing_url, &format!("dead-model-{idx}")),
            );
            fallbacks.push(Arc::new(
                Model::for_provider(
                    &cfg,
                    &provider,
                    &format!("dead-model-{idx}"),
                    std::sync::Arc::new(RedactionTable::empty()),
                )
                .unwrap(),
            ));
        }

        let (tmp, session, locks, redact) = ctx();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let mut metadata = BackupTurnMetadata::default();
        let result = turn_with_backup(
            &agent,
            None,
            &fallbacks,
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            Some(&mut metadata),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(metadata.fallback_tried.len(), MAX_FAILOVER_CANDIDATES);
    }

    #[test]
    fn failover_walk_orders_by_rank_after_configured_backup() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                backup: Some(BackupConfig {
                    provider: "explicit".into(),
                    model: "explicit-model".into(),
                }),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "explicit".into(),
            provider_with_model("http://localhost:2/v1", "explicit-model"),
        );
        let mut trusted_low = provider_with_model("http://localhost:3/v1", "trusted-low");
        trusted_low.trust = Some(ModelTrust::Trusted);
        trusted_low.quality_rank = Some(1);
        cfg.providers.insert("trusted-low".into(), trusted_low);
        let mut trusted_high = provider_with_model("http://localhost:4/v1", "trusted-high");
        trusted_high.trust = Some(ModelTrust::Trusted);
        trusted_high.quality_rank = Some(10);
        cfg.providers.insert("trusted-high".into(), trusted_high);
        let mut untrusted_best = provider_with_model("http://localhost:5/v1", "untrusted-best");
        untrusted_best.quality_rank = Some(100);
        cfg.providers
            .insert("untrusted-best".into(), untrusted_best);

        let primary = Model::for_provider(
            &cfg,
            "primary",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        let fallbacks = crate::engine::driver::build_failover_models(&cfg, &primary);
        let ids = fallbacks
            .iter()
            .map(|model| format!("{}:{}", model.provider_id(), model.model_id_ref()))
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "explicit:explicit-model",
                "untrusted-best:untrusted-best",
                "trusted-high:trusted-high"
            ]
        );
    }

    #[tokio::test]
    async fn hard_4xx_does_not_advance_failover_walk() {
        let primary_url = failing_server_with_status(400).await;
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("bad".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "bad",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let mut metadata = BackupTurnMetadata::default();
        let result = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            Some(&mut metadata),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(metadata.fallback_tried.len(), 1);
        let events = drain(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. }))
        );
    }

    #[tokio::test]
    async fn connect_failure_surfaces_as_network_class_before_ttft_budget() {
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("down".into(), provider_at("http://127.0.0.1:9/v1"));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "down",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("backup answers connection failure");
        let events = drain(&mut rx);
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::BackupUsed { error_class, .. }
                if error_class == &InferenceErrorClass::Network
        )));
    }

    /// The yellow banner is display-only and never enters model context: it
    /// rides a `TurnEvent`, not the history `Vec<Message>` the model is sent.
    #[tokio::test]
    async fn backup_banner_stays_out_of_model_context() {
        let primary_url = failing_server().await;
        let backup_url = sse_server("ok").await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let mut history: Vec<Message> = Vec::new();
        let _ = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut history,
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await
        .expect("backup answers");
        // The history the model sees carries the user turn + the backup's own
        // assistant turn — and NOTHING mentioning the fallback / primary
        // failure. No message contains a banner / "backup" annotation.
        let serialized = serde_json::to_string(&history).unwrap();
        assert!(
            !serialized.to_lowercase().contains("backup"),
            "fallback must leave no trace in model context, got: {serialized}"
        );
        assert!(
            !serialized.contains("failed"),
            "no failure annotation may enter model context"
        );
    }

    /// When the backup ALSO fails, the user sees the standard red inline error
    /// (the dependency's mechanism) and NO second banner is suppressed-away —
    /// exactly one `BackupUsed` (the attempt) then a red `InferenceFailed`.
    #[tokio::test]
    async fn backup_also_fails_surfaces_inline_error() {
        let primary_url = failing_server().await;
        let backup_url = failing_server().await; // backup fails too

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let res = run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await;
        assert!(res.is_err(), "both models failed → the turn errors");

        let events = drain(&mut rx);
        // Exactly one yellow banner (the single backup attempt).
        let banners = events
            .iter()
            .filter(|e| matches!(e, TurnEvent::BackupUsed { .. }))
            .count();
        assert_eq!(banners, 1, "exactly one fallback attempt → one banner");
        // The backup's own failure surfaced the red inline error.
        let reds = events
            .iter()
            .filter(|e| matches!(e, TurnEvent::InferenceFailed { .. }))
            .count();
        assert_eq!(reds, 1, "the backup's failure shows the red inline error");
    }

    /// No backup configured → a primary terminal failure hard-fails with the red inline
    /// error and NO banner (the dependency's behavior is preserved).
    #[tokio::test]
    async fn no_backup_hard_fails_with_red_error() {
        let primary_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let res = run(
            &agent,
            None,
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await;
        assert!(res.is_err());
        let events = drain(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. })),
            "no backup → no banner"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TurnEvent::InferenceFailed { .. }))
                .count(),
            1,
            "no backup → the primary's red inline error fires"
        );
    }

    /// Fallback is per-turn, not sticky: a second `turn_with_backup` call tries
    /// the PRIMARY again (it answers when healthy), proving the session is
    /// never pinned to the backup.
    #[tokio::test]
    async fn fallback_is_per_turn_not_sticky() {
        // Primary streams fine this time; backup is irrelevant.
        let primary_url = sse_server("from-primary").await;
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("primary answers");
        let events = drain(&mut rx);
        // The healthy primary answered — no fallback engaged.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. })),
            "a healthy primary must answer directly (per-turn primary-first)"
        );
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantText { text, .. } if text.contains("from-primary")
        )));
    }

    /// Backup resolution is keyed purely on the running model's
    /// `(provider, model)`, so any agent (the primary, or a subagent like
    /// `builder`/`explore`/`Swarm`) running that model resolves the SAME
    /// backup — the subagent-inheritance guarantee — and the backup may name a
    /// different provider. Verified against `build_backup_model` (the shared
    /// seam every turn-runner uses).
    #[test]
    fn backup_resolution_is_model_keyed_for_subagent_inheritance() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "flaky".into(),
            ProviderEntry {
                url: "http://localhost:9/v1".into(),
                backup: Some(BackupConfig {
                    provider: "reliable".into(),
                    model: "backup-model".into(),
                }),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "reliable".into(),
            ProviderEntry {
                url: "http://localhost:8/v1".into(),
                models: vec![ModelEntry {
                    id: "backup-model".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let running = Model::for_provider(
            &cfg,
            "flaky",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        let backup = crate::engine::driver::build_backup_model(&cfg, &running)
            .expect("a backup resolves for the running model");
        // The resolved backup points at the DIFFERENT configured provider/model
        // — independent of which agent is running `running`.
        assert_eq!(backup.provider_id(), "reliable");
        assert_eq!(backup.model_id_ref(), "backup-model");
    }

    #[test]
    fn backup_model_resolves_vault_named_secret_headers() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let mut store = crate::credentials::CredentialStore::from_vault(vault).unwrap();
        store.set_named_secret("backup-token", "vault-only-backup-secret-xyz");
        store.save().unwrap();

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "flaky".into(),
            ProviderEntry {
                url: "http://localhost:9/v1".into(),
                backup: Some(BackupConfig {
                    provider: "reliable".into(),
                    model: "backup-model".into(),
                }),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "reliable".into(),
            ProviderEntry {
                url: "http://localhost:8/v1".into(),
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer $secret:backup-token".into(),
                }],
                models: vec![ModelEntry {
                    id: "backup-model".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let running = Model::for_provider(
            &cfg,
            "flaky",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(
            crate::engine::driver::build_backup_model(&cfg, &running).is_none(),
            "backup with vault-only $secret must not build without a store"
        );
        let backup =
            crate::engine::driver::build_backup_model_with_store(&cfg, &running, Some(store))
                .expect("backup with injected vault store must resolve $secret headers");
        assert_eq!(backup.provider_id(), "reliable");
        assert_eq!(backup.model_id_ref(), "backup-model");
    }

    /// Command executor returning canned values by call order — startup resolves
    /// `values[0]`, a rebuild re-resolves `values[1]`, etc.
    struct SequencedCommandExecutor {
        values: Vec<String>,
        next: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::secret_command::CommandSecretExecutor for SequencedCommandExecutor {
        async fn run(
            &self,
            _argv: &[String],
        ) -> std::result::Result<String, crate::secret_command::CommandSecretError> {
            let index = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self
                .values
                .get(index)
                .cloned()
                .unwrap_or_else(|| "unexpected-extra-call".to_string()))
        }
    }

    fn claim_provider_ownership_row(
        db: &crate::db::Db,
        item_id: &str,
        project_root: &std::path::Path,
    ) {
        let root =
            crate::secret_ownership::canonical_owner_root(&project_root.display().to_string());
        let item_id = item_id.to_string();
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES (?1, 'provider', ?2, 0)",
                rusqlite::params![item_id, root],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// AC5 (HIGH #5, real path): a `CredentialsRejected` (401) on a command-backed
    /// provider drives the REAL `turn_with_backup` loop through one re-resolve +
    /// model-client rebuild + one retry. The ScriptedProvider serves 401 to the
    /// stale-token primary, then a completion to the fresh-token rebuilt retry.
    /// Proven on production code (no replica): the retry's captured Authorization
    /// header carries the FRESH token (a cache-invalidate-only reuse of the stale
    /// client would resend the stale token), the re-resolve executes exactly once,
    /// and two distinct `(call_id, ordinal)` rows are recorded.
    #[tokio::test]
    async fn credentials_rejected_rebuilds_client_and_retries_on_real_path() {
        use cockpit_test_support::provider::{CapturedRequest, ScriptedProvider, Turn, Usage};

        let provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 401,
                body: r#"{"error":{"message":"unauthorized"}}"#.into(),
            })
            .turn(Turn::Text("answered after credential rebuild".into()))
            .with_usage(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                total_tokens: 2,
                use_alias_names: false,
            })
            .start()
            .await;

        // Session whose vault holds the provider-owned command-backed secret.
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap().keep();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                root,
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        session.install_test_external_journal();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let mut store = crate::credentials::CredentialStore::from_vault(vault).unwrap();
        store
            .set_named_secret_command(
                "ghcmd",
                vec!["gh".to_string(), "auth".to_string(), "token".to_string()],
            )
            .unwrap();
        store.save().unwrap();
        claim_provider_ownership_row(&db, "ghcmd", &session.project_root);

        // startup resolves the stale token; the rebuild re-resolves the fresh one.
        let cache =
            crate::secret_command::CommandSecretCache::new(Arc::new(SequencedCommandExecutor {
                values: vec![
                    "stale-token-aaaaaaaaaaaa".to_string(),
                    "fresh-token-bbbbbbbbbbbb".to_string(),
                ],
                next: std::sync::atomic::AtomicUsize::new(0),
            }));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: provider.base_url(),
                // Trusted so the captured wire request is raw (no egress
                // redaction), letting the retry's Authorization header be
                // asserted against the freshly-resolved token directly.
                models: vec![ModelEntry {
                    id: "m".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer $secret:ghcmd".into(),
                }],
                timeout: TimeoutConfig {
                    ttft_secs: 5,
                    idle_secs: 5,
                },
                ..ProviderEntry::default()
            },
        );

        // Async startup pre-resolution → cache holds the stale token (exec 1).
        session
            .reresolve_provider_command_secrets(&cfg, "cloud")
            .await;
        assert_eq!(cache.exec_count(), 1);

        // The primary client, built from the owner-scoped store, sends the stale
        // token → the provider's first turn 401s.
        let table = Arc::new(RedactionTable::empty());
        let store_for_model = session.provider_credential_store(&cfg).unwrap();
        let primary = Arc::new(
            Model::for_provider_with_store(
                &cfg,
                "cloud",
                "m",
                table.clone(),
                |_name: &str| -> Option<String> { None },
                store_for_model,
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let call_id = Uuid::new_v4();
        let cwd = session.project_root.clone();

        let outcome = turn_with_backup(
            &agent,
            None,
            &[],
            &mut Vec::new(),
            Message::user("hello"),
            session.clone(),
            locks,
            table.clone(),
            cwd,
            crate::daemon::session_worker::SessionConfigHandle::detached(
                crate::daemon::session_worker::SessionConfigSnapshot::new(
                    0,
                    cfg.clone(),
                    crate::config::extended::ExtendedConfig::default(),
                ),
            ),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            call_id,
            None,
            None,
            None,
            &tx,
            None,
        )
        .await
        .unwrap();

        assert!(
            matches!(outcome, TurnOutcome::Done),
            "the rebuilt retry succeeds"
        );
        // Exactly one re-resolve on the rebuild (startup exec + one).
        assert_eq!(
            cache.exec_count(),
            2,
            "one and only one re-resolve on the rebuild"
        );

        // Two physical attempts under one call_id at distinct ordinals.
        let attempts = session
            .db
            .list_inference_requests_for_call(&call_id.to_string())
            .await
            .unwrap();
        assert_eq!(
            attempts.len(),
            2,
            "primary 401 + rebuilt retry are distinct rows"
        );
        assert_eq!(attempts[0].ordinal, 0);
        assert_eq!(attempts[1].ordinal, 1);

        // The retry dispatched a DISTINCT rebuilt client carrying the FRESH token.
        let captured = provider.captured();
        assert_eq!(captured.len(), 2, "primary 401 + one rebuilt retry");
        let auth = |req: &CapturedRequest| {
            req.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert!(
            auth(&captured[0]).contains("stale-token-aaaaaaaaaaaa"),
            "the primary sent the stale token"
        );
        assert!(
            auth(&captured[1]).contains("fresh-token-bbbbbbbbbbbb"),
            "the retry sent the freshly-resolved token — a distinct rebuilt client, \
             not a cache-invalidate-only reuse of the stale one"
        );
        let _ = drain(&mut rx);
    }

    /// AC3/AC5 (HIGH #3, real path): the credentials rebuild latch is scoped to
    /// the WHOLE logical dispatch, not per failover candidate. Primary 401 →
    /// rebuild-and-retry (one re-resolve) → that retry 5xxs → failover to a
    /// (also command-backed) backup → backup 401. The backup's 401 must NOT
    /// trigger a SECOND command rebuild/re-resolve: exactly one rebuild happens
    /// across the whole dispatch and the final error surfaces. Against a
    /// per-candidate latch the backup would rebuild too and `exec_count` would be
    /// 4, not 3.
    #[tokio::test]
    async fn credentials_latch_is_per_dispatch_not_per_failover_candidate() {
        use cockpit_test_support::provider::{ScriptedProvider, Turn};

        // Primary: 401 to the first attempt, then a failover-eligible 500 to the
        // rebuilt retry (repeat_last so internal 5xx retries all settle to 500).
        let primary_provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 401,
                body: r#"{"error":{"message":"unauthorized"}}"#.into(),
            })
            .turn(Turn::HttpError {
                status: 500,
                body: r#"{"error":{"message":"server"}}"#.into(),
            })
            .repeat_last()
            .start()
            .await;
        // Backup: 401 (repeat_last so a buggy second rebuild-retry still gets 401
        // rather than an unscripted request).
        let backup_provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 401,
                body: r#"{"error":{"message":"unauthorized"}}"#.into(),
            })
            .repeat_last()
            .start()
            .await;

        // Session whose vault holds BOTH providers' provider-owned command secrets.
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap().keep();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                root,
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        session.install_test_external_journal();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let mut store = crate::credentials::CredentialStore::from_vault(vault).unwrap();
        store
            .set_named_secret_command("ghcmd", vec!["gh-prog".to_string()])
            .unwrap();
        store
            .set_named_secret_command("bkcmd", vec!["bk-prog".to_string()])
            .unwrap();
        store.save().unwrap();
        claim_provider_ownership_row(&db, "ghcmd", &session.project_root);
        claim_provider_ownership_row(&db, "bkcmd", &session.project_root);

        let cache =
            crate::secret_command::CommandSecretCache::new(Arc::new(SequencedCommandExecutor {
                values: vec![],
                next: std::sync::atomic::AtomicUsize::new(0),
            }));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: primary_provider.base_url(),
                models: vec![ModelEntry {
                    id: "m".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer $secret:ghcmd".into(),
                }],
                timeout: TimeoutConfig {
                    ttft_secs: 5,
                    idle_secs: 5,
                },
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "local".into(),
            ProviderEntry {
                url: backup_provider.base_url(),
                models: vec![ModelEntry {
                    id: "bm".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer $secret:bkcmd".into(),
                }],
                timeout: TimeoutConfig {
                    ttft_secs: 5,
                    idle_secs: 5,
                },
                ..ProviderEntry::default()
            },
        );

        // Startup pre-resolution of BOTH providers' command secrets (exec 1 + 2)
        // so both models can be built.
        session
            .reresolve_provider_command_secrets(&cfg, "cloud")
            .await;
        session
            .reresolve_provider_command_secrets(&cfg, "local")
            .await;
        assert_eq!(cache.exec_count(), 2);

        let table = Arc::new(RedactionTable::empty());
        let cloud_store = session.provider_credential_store(&cfg).unwrap();
        let primary = Arc::new(
            Model::for_provider_with_store(
                &cfg,
                "cloud",
                "m",
                table.clone(),
                |_name: &str| -> Option<String> { None },
                cloud_store,
            )
            .unwrap(),
        );
        let local_store = session.provider_credential_store(&cfg).unwrap();
        let backup = Arc::new(
            Model::for_provider_with_store(
                &cfg,
                "local",
                "bm",
                table.clone(),
                |_name: &str| -> Option<String> { None },
                local_store,
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let cwd = session.project_root.clone();

        let result = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut Vec::new(),
            Message::user("hello"),
            session.clone(),
            locks,
            table.clone(),
            cwd,
            crate::daemon::session_worker::SessionConfigHandle::detached(
                crate::daemon::session_worker::SessionConfigSnapshot::new(
                    0,
                    cfg.clone(),
                    crate::config::extended::ExtendedConfig::default(),
                ),
            ),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await;

        assert!(result.is_err(), "the final backup 401 surfaces");
        // Exactly ONE command rebuild across the dispatch: startup(2) + the single
        // cloud rebuild(1). The backup's 401 does NOT rebuild again — a per-
        // candidate latch would make this 4.
        assert_eq!(
            cache.exec_count(),
            3,
            "at most one command rebuild-and-retry across the whole logical dispatch"
        );
        let _ = drain(&mut rx);
    }

    /// AC5 (real path): a provider whose credential is a STATIC key (no command-
    /// backed secret) that 401s is surfaced immediately — no re-resolve, no
    /// rebuild, no retry. Exactly one provider request; zero command exec. Against
    /// a no-eligibility-gate impl the dispatch would rebuild and retry (a second
    /// request).
    #[tokio::test]
    async fn static_provider_401_does_not_rebuild_or_retry() {
        use cockpit_test_support::provider::{ScriptedProvider, Turn};

        let provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 401,
                body: r#"{"error":{"message":"unauthorized"}}"#.into(),
            })
            .start()
            .await;

        let (tmp, session, locks, _redact) = ctx();
        // A command cache is installed, so the "not eligible" reason is the
        // provider having no command-backed reference (not a missing cache).
        let cache =
            crate::secret_command::CommandSecretCache::new(Arc::new(SequencedCommandExecutor {
                values: vec![],
                next: std::sync::atomic::AtomicUsize::new(0),
            }));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: provider.base_url(),
                models: vec![ModelEntry {
                    id: "m".into(),
                    ..ModelEntry::default()
                }],
                // A static literal credential — NOT a `$secret:` command reference.
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer static-literal-key".into(),
                }],
                timeout: TimeoutConfig {
                    ttft_secs: 5,
                    idle_secs: 5,
                },
                ..ProviderEntry::default()
            },
        );

        let table = Arc::new(RedactionTable::empty());
        let primary = Arc::new(Model::for_provider(&cfg, "cloud", "m", table.clone()).unwrap());
        let agent = agent_with(primary);

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = turn_with_backup(
            &agent,
            None,
            &[],
            &mut Vec::new(),
            Message::user("hello"),
            session.clone(),
            locks,
            table.clone(),
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached(
                crate::daemon::session_worker::SessionConfigSnapshot::new(
                    0,
                    cfg.clone(),
                    crate::config::extended::ExtendedConfig::default(),
                ),
            ),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await;

        assert!(result.is_err(), "the static-provider 401 surfaces");
        assert_eq!(
            cache.exec_count(),
            0,
            "no command re-resolve for a provider with no command-backed secret"
        );
        assert_eq!(
            provider.captured().len(),
            1,
            "exactly one provider request — no rebuild, no retry"
        );
        let _ = drain(&mut rx);
    }

    /// Decision (B), untrusted primary: failover may upgrade onto a trusted
    /// (self-hosted / no-log) endpoint, and may stay untrusted. Nothing is
    /// refused, so no custody diagnostic is recorded.
    #[test]
    fn untrusted_primary_may_fail_over_to_trusted_or_untrusted() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        let mut trusted = provider_with_model("http://localhost:2/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        cfg.providers.insert("trusted".into(), trusted);
        let mut untrusted = provider_with_model("http://localhost:3/v1", "untrusted-candidate");
        untrusted.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("untrusted".into(), untrusted);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        let ids: Vec<String> = fallbacks
            .iter()
            .map(|model| format!("{}:{}", model.provider_id(), model.model_id_ref()))
            .collect();

        assert!(
            ids.iter().any(|id| id == "trusted:trusted-candidate"),
            "an upgrade onto a trusted endpoint is permitted: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id == "untrusted:untrusted-candidate"),
            "staying at the primary's own class is permitted: {ids:?}"
        );
        assert!(refusals.is_empty(), "nothing to refuse: {refusals:?}");
    }

    /// Decision (B), trusted primary: failover is upgrade-only, so an untrusted
    /// candidate is refused with a typed error and recorded — never a silent
    /// downgrade onto a cloud endpoint. A trusted primary with no trusted
    /// candidate ends with an empty candidate list.
    #[test]
    fn trusted_primary_refuses_untrusted_failover_and_records_it() {
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model("http://localhost:1/v1", "main");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model("http://localhost:2/v1", "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        // The configured backup is refused rather than substituted.
        let (backup, backup_refusal) =
            crate::engine::driver::build_backup_model_with_diagnostics(&cfg, &primary);
        assert!(backup.is_none(), "a downgrade must not be substituted");
        let backup_refusal = backup_refusal.expect("the refusal must be recorded");
        assert_eq!(backup_refusal.provider, "cloud");
        assert_eq!(backup_refusal.model, "cloud-model");
        assert!(
            backup_refusal.reason.contains("upgrade-only"),
            "{}",
            backup_refusal.reason
        );

        // Discovery finds no admissible candidate either: typed failure, empty list.
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(fallbacks.is_empty(), "no trusted candidate exists");
        assert!(
            refusals
                .iter()
                .any(|refusal| refusal.provider == "cloud" && refusal.model == "cloud-model"),
            "every refused candidate is recorded: {refusals:?}"
        );

        // Adding a trusted candidate restores failover — the upgrade path works.
        let mut trusted = provider_with_model("http://localhost:3/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        cfg.providers.insert("trusted".into(), trusted);
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();
        let (fallbacks, _) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            fallbacks.iter().any(|model| {
                model.provider_id() == "trusted" && model.model_id_ref() == "trusted-candidate"
            }),
            "a trusted candidate is admissible for a trusted primary"
        );
    }

    /// The typed custody refusal must reach the session boundary as a
    /// user-visible reason. Without it the user sees only the primary's
    /// original inference error and cannot tell that failover existed but was
    /// refused on custody grounds.
    #[test]
    fn trusted_primary_custody_block_is_a_user_visible_reason() {
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model("http://localhost:1/v1", "main");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model("http://localhost:2/v1", "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let block = crate::engine::driver::failover_custody_block(&cfg, &primary)
            .expect("a trusted primary with only untrusted candidates is custody-blocked");
        assert_eq!(block.primary_provider, "primary");
        assert_eq!(block.primary_model, "main");
        assert!(
            block
                .refused
                .iter()
                .all(|refusal| refusal.kind.is_custody()),
            "only custody refusals belong in the block: {:?}",
            block.refused
        );
        let message = block.user_message();
        assert!(message.contains("no failover target"), "{message}");
        assert!(message.contains("upgrade-only"), "{message}");
        assert!(message.contains("cloud:cloud-model"), "{message}");
        assert!(message.contains("Configure a trusted backup"), "{message}");

        // An untrusted primary is never custody-blocked — failover may upgrade.
        let mut untrusted_cfg = cfg.clone();
        untrusted_cfg.providers.get_mut("primary").unwrap().trust = Some(ModelTrust::Untrusted);
        let untrusted_primary = Model::for_provider(
            &untrusted_cfg,
            "primary",
            "main",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(
            crate::engine::driver::failover_custody_block(&untrusted_cfg, &untrusted_primary)
                .is_none()
        );

        // Nor is a trusted primary that has an admissible trusted candidate.
        let mut ok_cfg = cfg.clone();
        let mut trusted = provider_with_model("http://localhost:3/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        ok_cfg.providers.insert("trusted".into(), trusted);
        let ok_primary = Model::for_provider(
            &ok_cfg,
            "primary",
            "main",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(crate::engine::driver::failover_custody_block(&ok_cfg, &ok_primary).is_none());
    }

    /// Item 2 (round 4). The typed custody reason must actually reach the user
    /// through `turn_with_backup`, not just format correctly.
    ///
    /// Previously `emit_failure_ui` and the custody-block branch were mutually
    /// exclusive — an empty candidate list forced `emit_failure_ui = true`, so
    /// `turn` emitted the plain error and the augmented event never ran. This
    /// drives a real trusted primary against a failing endpoint and asserts the
    /// `InferenceFailed` event the user sees carries the custody reason.
    #[tokio::test]
    async fn trusted_primary_custody_block_reaches_the_inference_failed_event() {
        let failing_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model(&failing_url, "primary-model");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model(&failing_url, "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "primary",
                "primary-model",
                Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        // The custody refusal means there is no candidate to hand in.
        let (fallbacks, _) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &agent.model);
        assert!(fallbacks.is_empty(), "custody refused every candidate");

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                cfg.clone(),
                crate::config::extended::ExtendedConfig::default(),
            ),
        );
        let result = turn_with_backup(
            &agent,
            None,
            &fallbacks,
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            config,
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await;
        assert!(result.is_err(), "the primary fails and has no failover");
        // The error chain still carries the typed reason for log/report surfaces.
        assert!(
            format!("{:#}", result.unwrap_err()).contains("upgrade-only"),
            "the custody reason must ride the error chain too"
        );

        drop(tx);
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let detail = events
            .iter()
            .find_map(|event| match event {
                TurnEvent::InferenceFailed { detail, .. } => Some(detail.clone()),
                _ => None,
            })
            .expect("the user-visible red inline error is emitted exactly once");
        assert!(detail.contains("no failover target"), "{detail}");
        assert!(detail.contains("upgrade-only"), "{detail}");
        assert!(detail.contains("cloud:cloud-model"), "{detail}");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TurnEvent::InferenceFailed { .. }))
                .count(),
            1,
            "exactly one red error — `turn`'s own emit must be suppressed"
        );
    }

    /// Eligibility rejections are never recorded or logged as custody refusals.
    #[test]
    fn eligibility_rejections_are_not_labelled_as_custody() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        cfg.providers.insert(
            "candidate".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "missing-context".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let (_, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            refusals
                .iter()
                .all(|refusal| refusal.kind.as_str() != "custody_downgrade"),
            "an untrusted primary can never produce a custody refusal: {refusals:?}"
        );
    }

    #[test]
    fn failover_discovery_includes_an_untrusted_invokable_model() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        cfg.providers.insert(
            "candidate".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "untrusted".into(),
                    subagent_invokable: Some(true),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let fallbacks = crate::engine::driver::build_failover_models(&cfg, &primary);

        assert!(fallbacks.iter().any(|model| {
            model.provider_id() == "candidate" && model.model_id_ref() == "untrusted"
        }));
    }
}

#[cfg(test)]
mod billing_overload_policy_tests {
    use super::*;
    use crate::engine::model::rig_boundary::{
        classify_terminal_failure, provider_recovery_signal_from_text,
    };
    use crate::engine::model::{
        InferenceErrorClass, ProviderRecoverySignal, failure_engages_backup,
    };
    use crate::engine::retry::{RetryDecision, classify, wait_for_decision};
    use rig::completion::CompletionError;

    fn provider_err(msg: &str) -> CompletionError {
        CompletionError::ProviderError(msg.to_string())
    }

    fn http_status(code: u16) -> CompletionError {
        CompletionError::HttpError(rig::http_client::Error::InvalidStatusCode(
            reqwest::StatusCode::from_u16(code).unwrap(),
        ))
    }

    #[test]
    fn billing_quota_is_fail_fast_and_cross_provider_only() {
        // (a) Code 1113 + every named billing phrase → BillingExhausted →
        //     BillingOrQuotaExhausted, and the retry layer fails fast (0 same-
        //     model retries).
        let billing_bodies = [
            "code 1113: account error",
            "insufficient balance to complete request",
            "no resource package available",
            "please recharge your account",
            "you have exceeded your current quota",
            "billing hard limit reached",
            "INSUFFICIENT BALANCE", // case-insensitive
        ];
        for body in billing_bodies {
            assert_eq!(
                provider_recovery_signal_from_text(body),
                ProviderRecoverySignal::BillingExhausted,
                "billing signal for {body:?}"
            );
            let classified = classify_terminal_failure(&provider_err(body));
            assert_eq!(
                classified.class,
                InferenceErrorClass::BillingOrQuotaExhausted,
                "{body:?}"
            );
            assert_eq!(
                classified.recovery,
                ProviderRecoverySignal::BillingExhausted
            );
            assert_eq!(
                classify(&provider_err(body)),
                RetryDecision::FailFast,
                "billing does zero same-model retries: {body:?}"
            );
        }

        // `1113` inside a longer number is NOT the structured code; fuzzy `quota`
        // prose is not a billing phrase.
        assert_eq!(
            provider_recovery_signal_from_text("request id 211137 completed"),
            ProviderRecoverySignal::None
        );
        // `1113` glued to an adjacent WORD (letter neighbor) is not a standalone
        // token either — only a genuinely delimited code counts as billing.
        assert_eq!(
            provider_recovery_signal_from_text("unexpected error1113 in stream"),
            ProviderRecoverySignal::None
        );
        assert_eq!(
            provider_recovery_signal_from_text("trace 1113abc dropped"),
            ProviderRecoverySignal::None
        );
        assert_eq!(
            provider_recovery_signal_from_text("your quota looks fine"),
            ProviderRecoverySignal::None
        );

        // (b) The observed 429 is preserved in diagnostics, separately from the
        //     class (billing observed as HTTP 429 with a billing body).
        let http_429_billing =
            CompletionError::HttpError(rig::http_client::Error::InvalidStatusCodeWithMessage(
                reqwest::StatusCode::from_u16(429).unwrap(),
                "insufficient balance".into(),
            ));
        let classified = classify_terminal_failure(&http_429_billing);
        assert_eq!(
            classified.class,
            InferenceErrorClass::BillingOrQuotaExhausted
        );
        assert_eq!(
            classified.observed_status,
            Some(429),
            "observed 429 retained separately from the class"
        );
        assert_eq!(
            classified.recovery,
            ProviderRecoverySignal::BillingExhausted
        );

        // (c) Backup engages; the action is top-up-or-switch-provider.
        assert!(failure_engages_backup(
            &InferenceErrorClass::BillingOrQuotaExhausted
        ));
        assert_eq!(
            suggested_action_for_failure_class(&InferenceErrorClass::BillingOrQuotaExhausted),
            "top_up_balance_or_switch_provider"
        );

        // (d) Cross-provider ONLY, exactly once. Primary provider `openai`;
        //     candidates [openai(same), anthropic(diff), groq(diff)].
        let providers = ["openai", "anthropic", "groq"];
        assert_eq!(
            select_next_backup_candidate(
                &providers,
                &[],
                "openai",
                ProviderRecoverySignal::BillingExhausted,
                false
            ),
            Some(1),
            "billing skips the same-provider candidate → first DIFFERENT provider"
        );
        assert_eq!(
            select_next_backup_candidate(
                &providers,
                &[1],
                "openai",
                ProviderRecoverySignal::BillingExhausted,
                true, // one billing backup already used
            ),
            None,
            "billing uses a different-provider backup EXACTLY once"
        );
        assert_eq!(
            select_next_backup_candidate(
                &["openai", "openai"],
                &[],
                "openai",
                ProviderRecoverySignal::BillingExhausted,
                false
            ),
            None,
            "billing NEVER uses a same-provider backup"
        );

        // (e) A true rate limit is not billing: Http(429) stays generic-retryable
        //     and does not engage the backup seam.
        assert_eq!(
            provider_recovery_signal_from_text("HTTP 429 rate limit exceeded"),
            ProviderRecoverySignal::None
        );
        assert_eq!(classify(&http_status(429)), RetryDecision::RetryAfter(None));
        assert!(!failure_engages_backup(&InferenceErrorClass::Http(429)));

        // (f) The DIAGNOSTIC status reports the RETAINED observed 429 even though
        // the billing class embeds no status, and the recommended action is
        // top-up-or-switch-provider (B4).
        let billing_failure = crate::engine::model::InferenceFailure {
            provider: "minimax".into(),
            model: "m".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::BillingOrQuotaExhausted,
            elapsed_ms: 1,
            retry_attempts: 1,
            detail: "insufficient balance".into(),
            observed_status: Some(429),
            recovery: ProviderRecoverySignal::BillingExhausted,
        };
        let diag = inference_failure_diagnostics(&billing_failure, "completions");
        assert_eq!(
            diag.provider_status,
            Some(429),
            "the billing diagnostic reports the retained observed 429"
        );
        assert_eq!(diag.recommended_action, "top_up_balance_or_switch_provider");
    }

    #[test]
    fn overload_retries_once_then_prefers_cross_provider() {
        // Only the named overload tokens are overload; each takes exactly one
        // same-model retry.
        for body in ["server_is_overloaded", "service_unavailable_error"] {
            assert_eq!(
                provider_recovery_signal_from_text(body),
                ProviderRecoverySignal::Overloaded,
                "{body:?}"
            );
            assert_eq!(
                classify(&provider_err(body)),
                RetryDecision::RetryOnce,
                "overload takes one same-model retry: {body:?}"
            );
        }
        // RetryOnce yields EXACTLY one same-model retry, keyed on whether the
        // overload retry has been SPENT (not the total failure count): an unused
        // overload retries; once spent, the next overload fails over to backup.
        assert!(wait_for_decision(RetryDecision::RetryOnce, 0, false).is_some());
        assert!(wait_for_decision(RetryDecision::RetryOnce, 1, true).is_none());
        // An overload that is NOT the first failure (a generic retry happened
        // first, so `failures == 1`) still gets its one same-model retry.
        assert!(wait_for_decision(RetryDecision::RetryOnce, 1, false).is_some());
        // After an overload retry is spent, an ordinary retryable failure fails
        // over to backup rather than continuing same-model retries.
        assert!(wait_for_decision(RetryDecision::Retry, 1, true).is_none());
        assert!(wait_for_decision(RetryDecision::Retry, 0, false).is_some());

        // A status-only 503 stays generic (retryable, not one-shot, recovery None).
        assert_eq!(
            provider_recovery_signal_from_text("HTTP 503 Service Unavailable"),
            ProviderRecoverySignal::None
        );
        assert_eq!(classify(&http_status(503)), RetryDecision::RetryAfter(None));

        // After the retry, prefer a DIFFERENT provider ahead of a same-provider
        // candidate. Primary `openai`; candidates [openai(same), anthropic(diff)].
        let providers = ["openai", "anthropic"];
        assert_eq!(
            select_next_backup_candidate(
                &providers,
                &[],
                "openai",
                ProviderRecoverySignal::Overloaded,
                false
            ),
            Some(1),
            "overload prefers a different provider"
        );
        assert_eq!(
            select_next_backup_candidate(
                &providers,
                &[1],
                "openai",
                ProviderRecoverySignal::Overloaded,
                false
            ),
            Some(0),
            "overload uses a same-provider candidate ONLY when no different remains"
        );
        assert_eq!(
            select_next_backup_candidate(
                &["openai"],
                &[],
                "openai",
                ProviderRecoverySignal::Overloaded,
                false
            ),
            Some(0),
            "a lone same-provider candidate is used when no different exists"
        );
    }
}
