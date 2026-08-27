use super::*;

fn next_active_model_state_generation(current: u64) -> Option<u64> {
    current.checked_add(1)
}

struct DefaultModelUpdateResult {
    outcome: crate::daemon::proto::DefaultModelUpdateOutcome,
    authoritative_selection: Option<crate::config::providers::ActiveModelRef>,
}

impl DefaultModelUpdateResult {
    fn not_requested(
        authoritative_selection: Option<crate::config::providers::ActiveModelRef>,
    ) -> Self {
        Self {
            outcome: crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
            authoritative_selection,
        }
    }

    fn verified(
        selection: crate::config::providers::ActiveModelRef,
        generation: u64,
        scope_label: String,
        unchanged: bool,
    ) -> Self {
        Self {
            outcome: crate::daemon::proto::DefaultModelUpdateOutcome::Verified {
                selection: selection.clone(),
                generation,
                scope_label,
                unchanged,
            },
            authoritative_selection: Some(selection),
        }
    }

    fn from_mutation(result: crate::config::providers::EffectiveDefaultMutationResult) -> Self {
        match result.selection {
            Some(selection) => Self::verified(
                selection,
                result.generation,
                result.scope_label,
                result.unchanged,
            ),
            // Unreachable from `/model`: a picker selection always requests a
            // concrete reference. Clearing is a Settings-only, config-only
            // operation with its own terminal result.
            None => Self::not_requested(None),
        }
    }
}

/// Durable session-model authority for the journaled session+default
/// transaction. Every mutation is a guarded CAS on `active_model_revision`.
///
/// Bound to exactly one session row. A stale journal naming a different
/// session is refused rather than silently CAS'd into this one — the driver
/// has no way to reach another session's row and must never appear to.
struct DriverSessionAuthority {
    session: std::sync::Arc<crate::session::Session>,
}

impl DriverSessionAuthority {
    fn require_own_session(&self, session_id: uuid::Uuid) -> Result<()> {
        if session_id != self.session.id {
            anyhow::bail!(
                "refusing to touch session {session_id} from the driver bound to session {}",
                self.session.id
            );
        }
        Ok(())
    }
}

impl crate::config::providers::SessionRevisionAuthority for DriverSessionAuthority {
    fn bound_session_id(&self) -> Option<uuid::Uuid> {
        Some(self.session.id)
    }

    fn current_revision(&mut self, session_id: uuid::Uuid) -> Result<Option<i64>> {
        self.require_own_session(session_id)?;
        self.session.active_model_revision().map(Some)
    }

    fn cas_set_active_model(
        &mut self,
        session_id: uuid::Uuid,
        expected_revision: i64,
        selection: &crate::config::providers::ActiveModelRef,
    ) -> Result<bool> {
        self.require_own_session(session_id)?;
        self.session
            .cas_set_active_model_ref(expected_revision, selection.clone())
    }
}

enum PreparedDefaultModelUpdate {
    Immediate(DefaultModelUpdateResult),
    /// Session+default must run as one journaled transaction at commit time.
    PendingReplace,
    #[cfg(test)]
    Test(DefaultModelWriteIntent),
}

/// What a `/model` selection asks of the effective default.
///
/// There is no "initialize if missing": plain Enter is session-only by
/// contract, so a session request can only ask for nothing or an explicit
/// replacement.
#[derive(Clone, Copy)]
pub(super) enum DefaultModelWriteIntent {
    None,
    Replace,
}

impl DefaultModelWriteIntent {
    /// Only an explicit `Ctrl+Enter` asks for a default write.
    ///
    /// Plain Enter is session-only by contract: it never invokes the
    /// effective-default mutation API and cannot alter `active_model` in any
    /// layer, so there is no "initialize if missing" branch here. A first
    /// default is established by `/settings`, `/setup model`, or `Ctrl+Enter`.
    pub(super) fn from_flags(persist_as_default: bool) -> Self {
        if persist_as_default {
            Self::Replace
        } else {
            Self::None
        }
    }
}

/// Deadline and exactly-once terminal-claim state for a timed model request.
pub(super) struct ModelSelectionTerminal<'a> {
    pub(super) deadline: std::time::Instant,
    pub(super) claimed: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModelSelectionCommitClaim {
    Untimed,
    Owned,
    Expired,
    Lost,
}

struct ModelSelectionTerminalEmission<'a> {
    claimed: Option<&'a std::sync::Arc<std::sync::atomic::AtomicBool>>,
    owned: bool,
}

struct ModelSelectionRejection {
    user_message: String,
    diagnostic_code: &'static str,
    /// The transaction crossed the durable commit boundary and this process
    /// could prove neither outcome. It is **not** terminal: no result may be
    /// emitted and the terminal slot must be released, so the recovery pass
    /// that finishes the journal emits the one correlated terminal event.
    pending_recovery: bool,
}

impl ModelSelectionRejection {
    fn deadline() -> Self {
        Self {
            user_message:
                "Model selection timed out before it could be committed; retry from /model."
                    .to_string(),
            diagnostic_code: "model_selection_deadline_exceeded",
            pending_recovery: false,
        }
    }

    fn failure(
        target: &crate::config::providers::ActiveModelRef,
        error: &str,
        diagnostic_code: &'static str,
    ) -> Self {
        Self {
            user_message: format!(
                "Could not switch to `{}/{}` — {error}. Keeping the confirmed model active.",
                target.provider, target.model
            ),
            diagnostic_code,
            pending_recovery: false,
        }
    }

    /// Map a typed effective-default failure onto the terminal rejection.
    ///
    /// Post-boundary outcomes keep the engine's own wording: a verified
    /// restoration says the default was not changed, while an unresolved
    /// transaction says recovery still owns it and never claims either value.
    fn from_effective_default(
        target: &crate::config::providers::ActiveModelRef,
        error: &crate::config::providers::EffectiveDefaultError,
    ) -> Self {
        if error.restored_after_boundary || error.recovery_pending {
            return Self {
                user_message: error.user_message.clone(),
                diagnostic_code: error.diagnostic_code,
                pending_recovery: error.recovery_pending,
            };
        }
        Self {
            user_message: format!(
                "Could not make `{}/{}` the default for new sessions — {}. The default was not changed and this session kept its model.",
                target.provider, target.model, error.user_message
            ),
            diagnostic_code: error.diagnostic_code,
            pending_recovery: false,
        }
    }
}

fn claim_model_selection_commit(
    terminal: Option<&ModelSelectionTerminal<'_>>,
) -> ModelSelectionCommitClaim {
    let Some(terminal) = terminal else {
        return ModelSelectionCommitClaim::Untimed;
    };
    if std::time::Instant::now() >= terminal.deadline {
        return ModelSelectionCommitClaim::Expired;
    }
    if terminal
        .claimed
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        ModelSelectionCommitClaim::Owned
    } else {
        ModelSelectionCommitClaim::Lost
    }
}

/// Switch the active model+provider live (`mid-session-model-
/// switch.md`), at the idle control boundary like every other primary swap.
/// Builds the new [`Model`](crate::engine::model::Model) for
/// `(provider, model)` from the layered config, threading the session's
/// effective redaction table (`self.redact`) so the new model keeps the
/// non-bypassable scrub chokepoint (GOALS §7), and inheriting the current
/// model's shutdown gate. On success it rebuilds
/// the **root primary** under the new model — preserving the root history so
/// the same conversation continues — persists the session's active-model row,
/// and refreshes the prunable projection. On any failure (provider not
/// configured, bad id, missing credentials) it **fails loudly** via a
/// [`TurnEvent::Notice`] and leaves the current model active (no silent
/// no-op, no crash). The prompt-cache break is expected and accepted.
impl Driver {
    pub(in crate::engine::driver) async fn set_active_model_live(
        &mut self,
        selection_id: uuid::Uuid,
        target: crate::config::providers::ActiveModelRef,
        default_write: DefaultModelWriteIntent,
        terminal: Option<ModelSelectionTerminal<'_>>,
        trigger: crate::session::ModelSwitchTrigger,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        let provider = target.provider.as_str();
        let deadline = terminal.as_ref().map(|terminal| terminal.deadline);
        let terminal_claimed = terminal.as_ref().map(|terminal| terminal.claimed);
        let model = target.model.as_str();
        tracing::info!(
            session_id = %self.session.id,
            %selection_id,
            provider,
            model,
            trigger = trigger.as_str(),
            generation = self.active_model_state_generation,
            "model selection received by driver"
        );
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            self.emit_model_selection_result(
                selection_id,
                &target,
                DefaultModelUpdateResult::not_requested(None),
                Some(ModelSelectionRejection::deadline()),
                ModelSelectionTerminalEmission {
                    claimed: terminal_claimed,
                    owned: false,
                },
                tx,
            )
            .await;
            return false;
        }
        // Every accepted selection must be followed by a strictly newer
        // ActiveModelState. Once the wire generation space is exhausted we
        // cannot preserve that fence, so fail closed before mutating either
        // the live model or its durable default.
        if next_active_model_state_generation(self.active_model_state_generation).is_none() {
            self.emit_model_selection_result(
                selection_id,
                &target,
                DefaultModelUpdateResult::not_requested(None),
                Some(ModelSelectionRejection::failure(
                    &target,
                    "active model state generation space is exhausted",
                    "model_selection_generation_exhausted",
                )),
                ModelSelectionTerminalEmission {
                    claimed: terminal_claimed,
                    owned: false,
                },
                tx,
            )
            .await;
            return false;
        }
        let old_session_selection = self.session.active_model_ref();
        let old_session_provider = old_session_selection
            .as_ref()
            .map(|value| value.provider.clone());
        let old_session_model = old_session_selection
            .as_ref()
            .map(|value| value.model.clone());
        if self.stack.is_empty() {
            self.emit_model_selection_result(
                selection_id,
                &target,
                DefaultModelUpdateResult::not_requested(None),
                Some(ModelSelectionRejection {
                    user_message: format!(
                        "Could not switch to `{provider}/{model}` because no root agent frame is available; retry after reattaching."
                    ),
                    diagnostic_code: "model_selection_no_active_frame",
                    pending_recovery: false,
                }),
                ModelSelectionTerminalEmission {
                    claimed: terminal_claimed,
                    owned: false,
                },
                tx,
            )
            .await;
            return false;
        }
        // ActiveModelRef is durable session/root state. Interactive child
        // frames may temporarily own the foreground, but changing only that
        // child would leave the parked resumable root split from the session
        // row and the state announced to clients.
        let root_idx = 0;
        let current = &self.stack[root_idx].agent.model;
        let old_prompt_cache_retention_preference = self.prompt_cache_retention_preference;
        self.prompt_cache_retention_preference = target.prompt_cache_retention;
        if current.provider_id() == provider
            && current.model_id_ref() == model
            && old_session_selection.as_ref() == Some(&target)
        {
            let prepared_default = match self.prepare_default_model(default_write) {
                Ok(prepared) => prepared,
                Err(rejection) => {
                    self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                    self.emit_model_selection_result(
                        selection_id,
                        &target,
                        DefaultModelUpdateResult::not_requested(None),
                        Some(rejection),
                        ModelSelectionTerminalEmission {
                            claimed: terminal_claimed,
                            owned: false,
                        },
                        tx,
                    )
                    .await;
                    return false;
                }
            };
            let terminal_owned = match claim_model_selection_commit(terminal.as_ref()) {
                ModelSelectionCommitClaim::Untimed => false,
                ModelSelectionCommitClaim::Owned => true,
                ModelSelectionCommitClaim::Lost => {
                    self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                    return false;
                }
                ModelSelectionCommitClaim::Expired => {
                    self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                    self.emit_model_selection_result(
                        selection_id,
                        &target,
                        DefaultModelUpdateResult::not_requested(None),
                        Some(ModelSelectionRejection::deadline()),
                        ModelSelectionTerminalEmission {
                            claimed: terminal_claimed,
                            owned: false,
                        },
                        tx,
                    )
                    .await;
                    return false;
                }
            };
            let default_update = match self
                .commit_prepared_default_model(
                    selection_id,
                    &target,
                    prepared_default,
                    true, // session already matches target
                    deadline,
                )
                .await
            {
                Ok(result) => result,
                Err(rejection) => {
                    self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                    if rejection.pending_recovery {
                        self.leave_terminal_to_recovery(
                            selection_id,
                            &target,
                            &rejection,
                            terminal_claimed,
                        );
                        return false;
                    }
                    self.emit_model_selection_result(
                        selection_id,
                        &target,
                        DefaultModelUpdateResult::not_requested(None),
                        Some(rejection),
                        ModelSelectionTerminalEmission {
                            claimed: terminal_claimed,
                            owned: terminal_owned,
                        },
                        tx,
                    )
                    .await;
                    return false;
                }
            };
            if matches!(
                &default_update.outcome,
                crate::daemon::proto::DefaultModelUpdateOutcome::Verified { .. }
            ) && default_update.authoritative_selection.as_ref() == Some(&target)
            {
                for idx in 0..self.stack.len() {
                    let retention =
                        self.resolve_prompt_cache_retention_for(&self.stack[idx].agent.model);
                    Arc::make_mut(&mut self.stack[idx].agent)
                        .params
                        .prompt_cache_retention = retention;
                }
            }
            self.record_model_switch_audit(crate::session::ModelSwitchAudit {
                from_provider: old_session_provider.as_deref(),
                from_model: old_session_model.as_deref(),
                to_provider: provider,
                to_model: model,
                trigger,
                outcome: crate::session::ModelSwitchOutcome::Noop,
                error: None,
            })
            .await;
            let saved_default = default_update.authoritative_selection.clone();
            self.emit_active_model_state_with_default(tx, saved_default)
                .await;
            if self.prompt_cache_retention_override.is_some() {
                self.emit_longcache_state(tx).await;
            }
            self.emit_model_selection_result(
                selection_id,
                &target,
                default_update,
                None,
                ModelSelectionTerminalEmission {
                    claimed: terminal_claimed,
                    owned: terminal_owned,
                },
                tx,
            )
            .await;
            return true;
        }
        // The new model inherits the running model's shutdown gate so a daemon
        // drain still refuses its dispatch.
        let new_model = match self.build_live_model(&target) {
            Ok(m) => Arc::new(m),
            Err(e) => {
                let error = format!("{e:#}");
                self.record_model_switch_audit(crate::session::ModelSwitchAudit {
                    from_provider: old_session_provider.as_deref(),
                    from_model: old_session_model.as_deref(),
                    to_provider: provider,
                    to_model: model,
                    trigger,
                    outcome: crate::session::ModelSwitchOutcome::BuildFailed,
                    error: Some(&error),
                })
                .await;
                // Fail loudly, keep the current model active.
                self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Model switch to `{provider}/{model}` failed — {error}. \
                             Keeping the current model active."
                        ),
                    })
                    .await;
                self.emit_active_model_state(tx).await;
                self.emit_model_selection_result(
                    selection_id,
                    &target,
                    DefaultModelUpdateResult::not_requested(None),
                    Some(ModelSelectionRejection::failure(
                        &target,
                        &error,
                        "model_selection_build_failed",
                    )),
                    ModelSelectionTerminalEmission {
                        claimed: terminal_claimed,
                        owned: false,
                    },
                    tx,
                )
                .await;
                return false;
            }
        };
        let rebuilt =
            match self.try_rebuild_frame_with_model(root_idx, new_model.clone(), &target, None) {
                Ok(agent) => Arc::new(agent),
                Err(_) if root_idx == 0 => {
                    Arc::new(self.rebuild_frame_with_model(root_idx, new_model, &target, None))
                }
                Err(e) => {
                    let error = format!("{e:#}");
                    self.record_model_switch_audit(crate::session::ModelSwitchAudit {
                        from_provider: old_session_provider.as_deref(),
                        from_model: old_session_model.as_deref(),
                        to_provider: provider,
                        to_model: model,
                        trigger,
                        outcome: crate::session::ModelSwitchOutcome::BuildFailed,
                        error: Some(&error),
                    })
                    .await;
                    self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: format!(
                                "Model switch to `{provider}/{model}` failed — {error}. \
                             Keeping the current model active."
                            ),
                        })
                        .await;
                    self.emit_active_model_state(tx).await;
                    self.emit_model_selection_result(
                        selection_id,
                        &target,
                        DefaultModelUpdateResult::not_requested(None),
                        Some(ModelSelectionRejection::failure(
                            &target,
                            &error,
                            "model_selection_rebuild_failed",
                        )),
                        ModelSelectionTerminalEmission {
                            claimed: terminal_claimed,
                            owned: false,
                        },
                        tx,
                    )
                    .await;
                    return false;
                }
            };
        let prepared_default = match self.prepare_default_model(default_write) {
            Ok(prepared) => prepared,
            Err(rejection) => {
                self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                self.emit_model_selection_result(
                    selection_id,
                    &target,
                    DefaultModelUpdateResult::not_requested(None),
                    Some(rejection),
                    ModelSelectionTerminalEmission {
                        claimed: terminal_claimed,
                        owned: false,
                    },
                    tx,
                )
                .await;
                return false;
            }
        };
        let terminal_owned = match claim_model_selection_commit(terminal.as_ref()) {
            ModelSelectionCommitClaim::Untimed => false,
            ModelSelectionCommitClaim::Owned => true,
            ModelSelectionCommitClaim::Lost => {
                self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                return false;
            }
            ModelSelectionCommitClaim::Expired => {
                self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                self.emit_model_selection_result(
                    selection_id,
                    &target,
                    DefaultModelUpdateResult::not_requested(None),
                    Some(ModelSelectionRejection::deadline()),
                    ModelSelectionTerminalEmission {
                        claimed: terminal_claimed,
                        owned: false,
                    },
                    tx,
                )
                .await;
                return false;
            }
        };
        // Session+default (Ctrl+Enter) journals session CAS with config; plain
        // Enter / initialize persist the session first, then config if needed.
        let is_session_and_default =
            matches!(prepared_default, PreparedDefaultModelUpdate::PendingReplace);
        #[cfg(test)]
        let is_session_and_default = is_session_and_default
            || matches!(
                prepared_default,
                PreparedDefaultModelUpdate::Test(DefaultModelWriteIntent::Replace)
            );
        if !is_session_and_default && let Err(e) = self.persist_active_model_session(&target) {
            let error = format!("{e:#}");
            self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
            let restored_provider = self.session.active_provider();
            let restored_model = self.session.active_model();
            self.record_model_switch_audit(crate::session::ModelSwitchAudit {
                from_provider: restored_provider.as_deref(),
                from_model: restored_model.as_deref(),
                to_provider: provider,
                to_model: model,
                trigger,
                outcome: crate::session::ModelSwitchOutcome::SendFailed,
                error: Some(&error),
            })
            .await;
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "Model switch to `{provider}/{model}` failed — {error}. \
                         Keeping the current model active."
                    ),
                })
                .await;
            self.emit_active_model_state(tx).await;
            self.emit_model_selection_result(
                selection_id,
                &target,
                DefaultModelUpdateResult::not_requested(None),
                Some(ModelSelectionRejection::failure(
                    &target,
                    &error,
                    "model_selection_session_persist_failed",
                )),
                ModelSelectionTerminalEmission {
                    claimed: terminal_claimed,
                    owned: terminal_owned,
                },
                tx,
            )
            .await;
            return false;
        }
        let default_update = match self
            .commit_prepared_default_model(selection_id, &target, prepared_default, false, deadline)
            .await
        {
            Ok(result) => result,
            Err(rejection) => {
                self.prompt_cache_retention_preference = old_prompt_cache_retention_preference;
                if rejection.pending_recovery {
                    self.leave_terminal_to_recovery(
                        selection_id,
                        &target,
                        &rejection,
                        terminal_claimed,
                    );
                    return false;
                }
                self.record_model_switch_audit(crate::session::ModelSwitchAudit {
                    from_provider: old_session_provider.as_deref(),
                    from_model: old_session_model.as_deref(),
                    to_provider: provider,
                    to_model: model,
                    trigger,
                    outcome: crate::session::ModelSwitchOutcome::SendFailed,
                    error: Some(rejection.user_message.as_str()),
                })
                .await;
                // The rejection message owns every claim about the default:
                // a pre-boundary failure says it did not change, a verified
                // restoration says both values were restored, and an
                // unresolved transaction says recovery still owns it.
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Model switch to `{provider}/{model}` failed — {}. \
                             Keeping the current model active.",
                            rejection.user_message
                        ),
                    })
                    .await;
                self.emit_active_model_state(tx).await;
                self.emit_model_selection_result(
                    selection_id,
                    &target,
                    DefaultModelUpdateResult::not_requested(None),
                    Some(rejection),
                    ModelSelectionTerminalEmission {
                        claimed: terminal_claimed,
                        owned: terminal_owned,
                    },
                    tx,
                )
                .await;
                return false;
            }
        };
        self.record_model_switch_audit(crate::session::ModelSwitchAudit {
            from_provider: old_session_provider.as_deref(),
            from_model: old_session_model.as_deref(),
            to_provider: provider,
            to_model: model,
            trigger,
            outcome: crate::session::ModelSwitchOutcome::Ok,
            error: None,
        })
        .await;
        self.stack[root_idx].agent = rebuilt;
        // A foreground child remains the schedule authority until it returns.
        // The rebuilt root becomes active naturally at the next root boundary.
        if self.active_frame_index() == Some(root_idx) {
            self.schedule.set_agent(self.stack[root_idx].agent.clone());
        }
        tracing::info!(provider, model, "active model switched live");
        // The model changed, so the prefix cache key changes — refresh the
        // prunable projection the chrome shows (cache-cold reflects the bust).
        self.emit_context_projection(tx).await;
        let saved_default = default_update.authoritative_selection.clone();
        self.emit_active_model_state_with_default(tx, saved_default)
            .await;
        if self.prompt_cache_retention_override.is_some() {
            self.emit_longcache_state(tx).await;
        }
        self.emit_model_selection_result(
            selection_id,
            &target,
            default_update,
            None,
            ModelSelectionTerminalEmission {
                claimed: terminal_claimed,
                owned: terminal_owned,
            },
            tx,
        )
        .await;
        true
    }

    /// Emit the correlated terminal result for each transaction a recovery
    /// pass converged on this session's behalf.
    ///
    /// The originating call deliberately emitted nothing (it could prove
    /// neither outcome), so this is the one terminal result for that
    /// operation. The generation is this driver's own active-model-state
    /// counter, which is exactly what a client's terminal gate compares
    /// against — a recovery pass cannot know it.
    pub(in crate::engine::driver) async fn emit_recovered_default_terminals(
        &mut self,
        transactions: Vec<crate::config::providers::RecoveredTransaction>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> std::result::Result<(), String> {
        use crate::config::providers::{RecoveredOutcome, TransactionCorrelation};

        for transaction in transactions {
            if transaction.correlation.session_id() != self.session.id {
                continue;
            }
            // A default-update journal carries its receipt authority only after
            // the sealing fence; `None` is a pending handoff that must never be
            // delivered as a terminal (see `TransactionCorrelation` docs). Skip
            // it and leave it for a later sealing pass — an unsealed entry (e.g.
            // a legacy ambient `DefaultUpdate` journal after upgrade) must not
            // abort delivery of the sibling `ModelSelection` terminals queued
            // behind it in the same batch.
            if matches!(
                &transaction.correlation,
                TransactionCorrelation::DefaultUpdate {
                    authority: None,
                    ..
                } | TransactionCorrelation::RetainedDefaultUpdate {
                    authority: None,
                    ..
                }
            ) {
                tracing::warn!(
                    session_id = %self.session.id,
                    "skipping terminal delivery for an unsealed (pending) recovered default-update journal"
                );
                continue;
            }
            // A retained `SetDefaultModel` is config-only. Its terminal
            // generation is the exact config snapshot generation sealed in
            // the durable authority binding, not this driver's unrelated
            // active-model-state sequence. Advancing that sequence here used
            // to make recovered receipts disagree with their DB authority
            // columns and with the direct (non-recovery) result.
            let retained_default = matches!(
                &transaction.correlation,
                TransactionCorrelation::RetainedDefaultUpdate { .. }
            );
            let generation = if retained_default {
                transaction
                    .correlation
                    .default_update_authority()
                    .ok_or_else(|| {
                        "recovered retained default has no sealed authority receipt binding"
                            .to_string()
                    })?
                    .config_generation
            } else {
                let Some(generation) =
                    next_active_model_state_generation(self.active_model_state_generation)
                else {
                    tracing::error!(
                        session_id = %self.session.id,
                        "cannot reconcile a recovered model transaction: active model state generation space is exhausted"
                    );
                    return Err(
                        "active model state generation space is exhausted while recording a recovered default receipt"
                            .to_string(),
                    );
                };
                generation
            };
            // A recovered `Applied` for a *session+default* transaction says
            // the durable authorities hold the target while this driver
            // returned before its root swap, so the live agent is still the
            // old model: rebuild it here, on the control loop (single
            // writer), before any event claims success.
            //
            // A `DefaultUpdate` correlation is `SetDefaultModel` — config-only
            // by contract. It must never switch the running session (AC6/AC9),
            // so it is deliberately excluded.
            let swapped = match (&transaction.correlation, &transaction.outcome) {
                (
                    TransactionCorrelation::ModelSelection { .. },
                    RecoveredOutcome::Applied { .. },
                ) => match transaction.requested.as_ref() {
                    Some(requested) => self.adopt_recovered_session_model(requested),
                    None => Ok(()),
                },
                _ => Ok(()),
            };
            if !retained_default {
                self.active_model_state_generation = generation;
            }
            if let Err(error) = swapped {
                // Never claim a model the running agent is not using.
                let message = format!(
                    "The default was updated, but this session could not switch to the recovered \
                     model — {error:#}. Re-select it from /model."
                );
                match transaction.correlation {
                    TransactionCorrelation::DefaultUpdate {
                        default_update_id,
                        authority,
                        ..
                    }
                    | TransactionCorrelation::RetainedDefaultUpdate {
                        default_update_id,
                        authority,
                        ..
                    } => {
                        let authority = authority.ok_or_else(|| {
                            "recovered retained default has no sealed authority receipt binding"
                                .to_string()
                        })?;
                        let outcome =
                            crate::daemon::proto::DefaultModelStandaloneOutcome::Rejected {
                                user_message: message,
                                diagnostic_code: "model_selection_recovered_rebuild_failed"
                                    .to_string(),
                            };
                        let encoded = serde_json::to_string(&outcome).map_err(|error| {
                            format!("encoding recovered default-model terminal receipt: {error}")
                        })?;
                        let receipt = self
                            .session
                            .db
                            .record_default_model_update_receipt(
                                self.session.id,
                                default_update_id,
                                crate::db::session_log::DefaultModelUpdateReceipt {
                                    outcome_json: encoded,
                                    authority_revision: Some(authority.authority_revision.clone()),
                                    config_generation: Some(authority.config_generation),
                                },
                            )
                            .await
                            .map_err(|error| {
                                format!(
                                    "persisting recovered default-model terminal receipt: {error:#}"
                                )
                            })?;
                        if matches!(
                            receipt,
                            crate::db::session_log::DefaultModelUpdateReceiptWrite::Recorded
                        ) {
                            let _ = tx
                                .send(TurnEvent::DefaultModelUpdateResult {
                                    default_update_id,
                                    outcome,
                                })
                                .await;
                        }
                    }
                    TransactionCorrelation::ModelSelection { selection_id, .. } => {
                        let Some(requested) = transaction.requested.clone() else {
                            continue;
                        };
                        let _ = tx
                            .send(TurnEvent::ModelSelectionResult {
                                selection_id,
                                provider: requested.provider.clone(),
                                model: requested.model.clone(),
                                reasoning_effort: requested
                                    .reasoning_effort
                                    .as_ref()
                                    .map(|effort| effort.value.clone()),
                                thinking_mode: requested.thinking_mode,
                                prompt_cache_retention: requested.prompt_cache_retention,
                                outcome: crate::daemon::proto::ModelSelectionOutcome::Rejected {
                                    user_message: message,
                                    diagnostic_code: "model_selection_recovered_rebuild_failed"
                                        .to_string(),
                                },
                            })
                            .await;
                    }
                }
                continue;
            }
            match transaction.correlation {
                TransactionCorrelation::DefaultUpdate {
                    default_update_id,
                    authority,
                    ..
                }
                | TransactionCorrelation::RetainedDefaultUpdate {
                    default_update_id,
                    authority,
                    ..
                } => {
                    let authority = authority.ok_or_else(|| {
                        "recovered retained default has no sealed authority receipt binding"
                            .to_string()
                    })?;
                    let outcome = match &transaction.outcome {
                        RecoveredOutcome::Applied { selection, .. } => {
                            crate::daemon::proto::DefaultModelStandaloneOutcome::Applied {
                                selection: selection.clone(),
                                generation,
                                authority_revision: authority.authority_revision.clone(),
                                scope_label: transaction.scope_label.clone(),
                                unchanged: false,
                            }
                        }
                        RecoveredOutcome::Restored { session, .. } => {
                            crate::daemon::proto::DefaultModelStandaloneOutcome::Rejected {
                                user_message: format!(
                                    "The default model was not changed — the update could not be \
                                     completed. The previous default was restored and {}.",
                                    session.describe()
                                ),
                                diagnostic_code: "effective_default_restored_after_boundary"
                                    .to_string(),
                            }
                        }
                    };
                    let encoded = serde_json::to_string(&outcome).map_err(|error| {
                        format!("encoding recovered default-model terminal receipt: {error}")
                    })?;
                    let (authority_revision, config_generation) = match &outcome {
                        crate::daemon::proto::DefaultModelStandaloneOutcome::Applied {
                            authority_revision,
                            ..
                        } => {
                            if authority_revision != &authority.authority_revision {
                                return Err(
                                    "recovered retained default receipt revision disagrees with its journal binding"
                                        .to_string(),
                                );
                            }
                            (
                                Some(authority.authority_revision.clone()),
                                Some(authority.config_generation),
                            )
                        }
                        crate::daemon::proto::DefaultModelStandaloneOutcome::Rejected {
                            ..
                        } => (
                            Some(authority.authority_revision.clone()),
                            Some(authority.config_generation),
                        ),
                    };
                    let receipt = self
                        .session
                        .db
                        .record_default_model_update_receipt(
                            self.session.id,
                            default_update_id,
                            crate::db::session_log::DefaultModelUpdateReceipt {
                                outcome_json: encoded,
                                authority_revision,
                                config_generation,
                            },
                        )
                        .await
                        .map_err(|error| {
                            format!(
                                "persisting recovered default-model terminal receipt: {error:#}"
                            )
                        })?;
                    if matches!(
                        receipt,
                        crate::db::session_log::DefaultModelUpdateReceiptWrite::Recorded
                    ) {
                        let _ = tx
                            .send(TurnEvent::DefaultModelUpdateResult {
                                default_update_id,
                                outcome,
                            })
                            .await;
                    }
                }
                TransactionCorrelation::ModelSelection { selection_id, .. } => {
                    let Some(requested) = transaction.requested.clone() else {
                        continue;
                    };
                    let outcome = match &transaction.outcome {
                        RecoveredOutcome::Applied { selection, .. } => {
                            crate::daemon::proto::ModelSelectionOutcome::Applied {
                                active_state: Box::new(
                                    crate::daemon::proto::ModelSelectionActiveState {
                                        selection: requested.clone(),
                                        default_selection: selection.clone(),
                                        diverged: selection.as_ref() != Some(&requested),
                                        generation,
                                    },
                                ),
                                default_update:
                                    crate::daemon::proto::DefaultModelUpdateOutcome::Verified {
                                        selection: requested.clone(),
                                        generation,
                                        scope_label: transaction.scope_label.clone(),
                                        unchanged: false,
                                    },
                            }
                        }
                        RecoveredOutcome::Restored { session, .. } => {
                            crate::daemon::proto::ModelSelectionOutcome::Rejected {
                                user_message: format!(
                                    "The model switch did not complete. The previous default was \
                                     restored and {}.",
                                    session.describe()
                                ),
                                diagnostic_code: "effective_default_restored_after_boundary"
                                    .to_string(),
                            }
                        }
                    };
                    let _ = tx
                        .send(TurnEvent::ModelSelectionResult {
                            selection_id,
                            provider: requested.provider.clone(),
                            model: requested.model.clone(),
                            reasoning_effort: requested
                                .reasoning_effort
                                .as_ref()
                                .map(|effort| effort.value.clone()),
                            thinking_mode: requested.thinking_mode,
                            prompt_cache_retention: requested.prompt_cache_retention,
                            outcome,
                        })
                        .await;
                }
            }
        }
        Ok(())
    }

    /// Bring the live root agent onto a model that recovery already committed
    /// to both durable authorities.
    ///
    /// This is the swap `set_active_model_live` would have performed had the
    /// transaction completed in-process. It runs on the driver's control loop,
    /// so it keeps the single-writer discipline the rest of the swap path
    /// relies on. A no-op when the root already runs that model.
    fn adopt_recovered_session_model(
        &mut self,
        requested: &crate::config::providers::ActiveModelRef,
    ) -> Result<()> {
        if self.stack.is_empty() {
            anyhow::bail!("no root agent frame is available");
        }
        let root_idx = 0;
        let running = &self.stack[root_idx].agent.model;
        if running.provider_id() == requested.provider && running.model_id_ref() == requested.model
        {
            return Ok(());
        }
        let new_model = Arc::new(self.build_live_model(requested)?);
        let rebuilt =
            match self.try_rebuild_frame_with_model(root_idx, new_model.clone(), requested, None) {
                Ok(agent) => Arc::new(agent),
                Err(_) => {
                    Arc::new(self.rebuild_frame_with_model(root_idx, new_model, requested, None))
                }
            };
        self.stack[root_idx].agent = rebuilt;
        if self.active_frame_index() == Some(root_idx) {
            self.schedule.set_agent(self.stack[root_idx].agent.clone());
        }
        self.prompt_cache_retention_preference = requested.prompt_cache_retention;
        Ok(())
    }

    /// A post-boundary transaction whose outcome this process could not prove
    /// is **not** terminal. Emit nothing, release the terminal slot, and let
    /// the recovery pass that converges the journal emit the one correlated
    /// terminal result. The client keeps showing non-terminal pending wording.
    fn leave_terminal_to_recovery(
        &self,
        selection_id: uuid::Uuid,
        target: &crate::config::providers::ActiveModelRef,
        rejection: &ModelSelectionRejection,
        claimed: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) {
        // The claim is deliberately *kept*. Releasing it would let the
        // worker's deadline path win the race and emit a `Rejected` for a
        // transaction that already crossed the durable commit boundary — and
        // recovery would then emit a second terminal for the same
        // `selection_id`. Recovery emits directly through the driver, which
        // does not consult this flag, so holding it makes exactly one terminal
        // result possible.
        let _ = claimed;
        tracing::warn!(
            session_id = %self.session.id,
            %selection_id,
            provider = %target.provider,
            model = %target.model,
            diagnostic_code = rejection.diagnostic_code,
            "default-model transaction is pending recovery; no terminal result emitted"
        );
    }

    async fn emit_model_selection_result(
        &self,
        selection_id: uuid::Uuid,
        target: &crate::config::providers::ActiveModelRef,
        default_update: DefaultModelUpdateResult,
        rejection: Option<ModelSelectionRejection>,
        terminal: ModelSelectionTerminalEmission<'_>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        if !terminal.owned
            && terminal
                .claimed
                .is_some_and(|claimed| claimed.swap(true, std::sync::atomic::Ordering::AcqRel))
        {
            return;
        }
        let applied = rejection.is_none();
        tracing::info!(
            session_id = %self.session.id,
            %selection_id,
            provider = %target.provider,
            model = %target.model,
            generation = self.active_model_state_generation,
            applied,
            "model selection terminal result"
        );
        // Config-watch refresh is asynchronous. A successful write is already
        // authoritative for this terminal result even if the worker's live
        // snapshot still contains the prior default for a few milliseconds.
        let terminal_default_selection = default_update
            .authoritative_selection
            .or_else(|| self.live_config_active_model());
        let terminal_diverged = terminal_default_selection.as_ref() != Some(target);
        let _ = tx
            .send(TurnEvent::ModelSelectionResult {
                selection_id,
                provider: target.provider.clone(),
                model: target.model.clone(),
                reasoning_effort: target
                    .reasoning_effort
                    .as_ref()
                    .map(|effort| effort.value.clone()),
                thinking_mode: target.thinking_mode,
                prompt_cache_retention: target.prompt_cache_retention,
                outcome: if let Some(rejection) = rejection {
                    crate::daemon::proto::ModelSelectionOutcome::Rejected {
                        user_message: rejection.user_message,
                        diagnostic_code: rejection.diagnostic_code.to_string(),
                    }
                } else {
                    crate::daemon::proto::ModelSelectionOutcome::Applied {
                        active_state: Box::new(crate::daemon::proto::ModelSelectionActiveState {
                            selection: target.clone(),
                            default_selection: terminal_default_selection,
                            diverged: terminal_diverged,
                            generation: self.active_model_state_generation,
                        }),
                        default_update: default_update.outcome,
                    }
                },
            })
            .await;
    }

    /// Build a fresh [`Model`](crate::engine::model::Model) for `(provider,
    /// model)` from the layered config (honoring the test-injected config in
    /// tests), threading the session's effective redaction table, inheriting
    /// the running model's shutdown gate, and preserving the running
    /// wire-API self-heal state only for same-identity refresh rebuilds. The
    /// new model's reasoning params are re-resolved from the config's
    /// active-model thinking mode and ride on the rebuilt root agent. Errors
    /// propagate so the caller can surface them (unconfigured provider / bad
    /// id / missing key).
    pub(in crate::engine::driver) fn build_live_model(
        &self,
        active: &crate::config::providers::ActiveModelRef,
    ) -> Result<crate::engine::model::Model> {
        // Model selection is session/root state. A foreground child may be
        // pinned to a different provider or config layer, and must never lend
        // those runtime details to a rebuilt root model.
        let running = self.stack[0].agent.model.clone();
        self.build_live_model_for_running_with_active(&running, active)
    }

    pub(in crate::engine::driver) fn build_live_model_for_running(
        &self,
        running: &crate::engine::model::Model,
        provider: &str,
        model: &str,
    ) -> Result<crate::engine::model::Model> {
        let active = crate::config::providers::ActiveModelRef {
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        };
        self.build_live_model_for_running_with_active(running, &active)
    }

    fn build_live_model_for_running_with_active(
        &self,
        running: &crate::engine::model::Model,
        active: &crate::config::providers::ActiveModelRef,
    ) -> Result<crate::engine::model::Model> {
        let mut providers = self.live_providers_config()?;
        providers.active_model = Some(active.clone());
        let env_overlay = self.stack[0].agent.env_overlay.clone();
        // Owner-scoped: a swapped-in provider model may only resolve `$secret:`
        // names owned by (provider, this session's project root).
        let store = self.session.provider_credential_store(&providers)?;
        let mut built = crate::engine::model::Model::for_provider_with_store(
            &providers,
            &active.provider,
            &active.model,
            self.redact.clone(),
            move |name| {
                env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(name)
                    .cloned()
            },
            store,
        )?
        .with_shutdown_gate(running.shutdown_gate());
        if running.provider_id() == active.provider && running.model_id_ref() == active.model {
            built = built.with_live_wire_api(running);
        }
        let built = match running.config_path() {
            Some(path) => built.with_config_path(path.to_path_buf()),
            None => built,
        };
        Ok(built)
    }

    fn live_config_active_model(&self) -> Option<crate::config::providers::ActiveModelRef> {
        self.live_providers_config().ok()?.active_model
    }

    #[cfg(test)]
    fn authoritative_config_active_model(
        &self,
    ) -> Option<crate::config::providers::ActiveModelRef> {
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            return providers.active_model.clone();
        }
        // Session-scoped code reads config through the driver's live snapshot,
        // never straight from disk.
        self.live_config_active_model()
    }

    /// Resolve what the terminal default-update outcome will be, without
    /// touching any authority.
    ///
    /// Only two intents exist: `None` (plain Enter — session-only, so the
    /// default is reported as `NotRequested`) and `Replace` (Ctrl+Enter — one
    /// journaled transaction performed at commit time). There is deliberately
    /// no "initialize if missing" path: a session-only selection can never
    /// write `active_model` in any layer.
    fn prepare_default_model(
        &self,
        intent: DefaultModelWriteIntent,
    ) -> std::result::Result<PreparedDefaultModelUpdate, ModelSelectionRejection> {
        if matches!(intent, DefaultModelWriteIntent::None) {
            return Ok(PreparedDefaultModelUpdate::Immediate(
                DefaultModelUpdateResult::not_requested(self.live_config_active_model()),
            ));
        }

        #[cfg(test)]
        if self.test_providers_override.is_some() || self.test_fail_next_active_model_config_write {
            return Ok(PreparedDefaultModelUpdate::Test(intent));
        }

        // The explicit replace is a single journaled transaction at commit
        // time (guarded session CAS + config). Preparation only resolves that
        // the call is pending; no authority changes here.
        Ok(PreparedDefaultModelUpdate::PendingReplace)
    }

    /// Run one journaled effective-default mutation off the async runtime.
    ///
    /// The deadline is enforced by requesting cancellation and then honoring
    /// whatever the transaction actually decided: cancellation is only
    /// observed *before* the durable commit boundary, so a transaction that
    /// already crossed it still reports its verified terminal outcome instead
    /// of a spurious timeout rejection.
    async fn await_effective_default_mutation(
        task: tokio::task::JoinHandle<
            std::result::Result<
                crate::config::providers::EffectiveDefaultMutationResult,
                crate::config::providers::EffectiveDefaultError,
            >,
        >,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        deadline: Option<std::time::Instant>,
        target: &crate::config::providers::ActiveModelRef,
    ) -> std::result::Result<
        crate::config::providers::EffectiveDefaultMutationResult,
        ModelSelectionRejection,
    > {
        let mut task = task;
        let joined = match deadline {
            Some(deadline) => {
                match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut task)
                    .await
                {
                    Ok(joined) => joined,
                    Err(_) => {
                        cancelled.store(true, std::sync::atomic::Ordering::Release);
                        task.await
                    }
                }
            }
            None => task.await,
        };
        let joined = joined.map_err(|error| {
            ModelSelectionRejection::failure(
                target,
                &format!("joining the default-model transaction: {error}"),
                "default_model_write_failed",
            )
        })?;
        joined.map_err(|error| {
            if error.diagnostic_code == "effective_default_cancelled" {
                ModelSelectionRejection::deadline()
            } else {
                ModelSelectionRejection::from_effective_default(target, &error)
            }
        })
    }

    async fn commit_prepared_default_model(
        &mut self,
        selection_id: uuid::Uuid,
        target: &crate::config::providers::ActiveModelRef,
        prepared: PreparedDefaultModelUpdate,
        session_already_persisted: bool,
        deadline: Option<std::time::Instant>,
    ) -> std::result::Result<DefaultModelUpdateResult, ModelSelectionRejection> {
        match prepared {
            PreparedDefaultModelUpdate::Immediate(result) => Ok(result),
            PreparedDefaultModelUpdate::PendingReplace => {
                self.run_session_and_default_transaction(
                    selection_id,
                    target,
                    session_already_persisted,
                    deadline,
                )
                .await
            }
            #[cfg(test)]
            PreparedDefaultModelUpdate::Test(intent) => {
                self.update_default_model_for_test(target, intent)
            }
        }
    }

    /// The Ctrl+Enter all-or-nothing transaction: one journaled operation
    /// commits the guarded session revision and the effective default, or
    /// converges both back to their recorded prior values.
    async fn run_session_and_default_transaction(
        &mut self,
        selection_id: uuid::Uuid,
        target: &crate::config::providers::ActiveModelRef,
        session_already_persisted: bool,
        deadline: Option<std::time::Instant>,
    ) -> std::result::Result<DefaultModelUpdateResult, ModelSelectionRejection> {
        #[cfg(test)]
        if self.test_fail_next_active_model_config_write {
            self.test_fail_next_active_model_config_write = false;
            return Err(ModelSelectionRejection::failure(
                target,
                "test injected active model config write failure",
                "default_model_write_failed",
            ));
        }

        // This legacy Ctrl+Enter path still owns an ambient effective-default
        // transaction (unlike the retained daemon RPC). It must therefore
        // participate in the same publication order as SetWorkspaceTrust:
        // either it completes under the policy observed before the durable
        // transition, or it begins only after the worker's shared policy cell
        // and retained snapshot have been projected. Without this gate a
        // driver could capture Trust, then write a project layer after an
        // IgnoreConfig decision committed.
        let _config_publication_guard = crate::daemon::server::CONFIG_PUBLICATION_RPC_LOCK
            .lock()
            .await;

        let prior_session = self
            .session
            .active_model_ref()
            .unwrap_or_else(|| target.clone());
        // The guard revision is the whole point of the CAS. Reading it must
        // not be papered over with a default: a wrong guard would either fail
        // every commit or, worse, match a row it does not describe.
        let expected_revision = match self.session.active_model_revision() {
            Ok(revision) => revision,
            Err(error) => {
                return Err(ModelSelectionRejection::failure(
                    target,
                    &format!("the session's active-model revision could not be read: {error:#}"),
                    "model_selection_session_revision_unreadable",
                ));
            }
        };
        let session_id = self.session.id;
        let session = self.session.clone();
        let cwd = self.cwd.clone();
        let target_for_write = target.clone();
        let trust_policy = crate::config::trust::current_workspace_trust_policy();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_cancelled = std::sync::Arc::clone(&cancelled);

        let task = tokio::task::spawn_blocking(move || {
            let _guard = trust_policy.map(crate::config::trust::enter_workspace_trust_policy);
            let mut authority = DriverSessionAuthority { session };
            // A no-op switch already holds the target session model, so only
            // the config half participates; the reload is still verified.
            let participant = if session_already_persisted {
                None
            } else {
                Some(crate::config::providers::SessionDefaultParticipant {
                    session_id,
                    prior: prior_session,
                    expected_revision,
                    authority: &mut authority,
                })
            };
            crate::config::providers::mutate_effective_default(
                &cwd,
                Some(&target_for_write),
                crate::config::providers::ActiveModelWriteMode::Replace,
                participant,
                Some(task_cancelled.as_ref()),
                // Recorded in the journal so a transaction this process
                // cannot finish still yields exactly one correlated terminal
                // result, emitted by the recovery pass that does finish it.
                Some(
                    crate::config::providers::TransactionCorrelation::ModelSelection {
                        selection_id,
                        session_id,
                    },
                ),
            )
        });

        Self::await_effective_default_mutation(task, cancelled, deadline, target)
            .await
            .map(DefaultModelUpdateResult::from_mutation)
    }

    #[cfg(test)]
    fn update_default_model_for_test(
        &mut self,
        target: &crate::config::providers::ActiveModelRef,
        intent: DefaultModelWriteIntent,
    ) -> std::result::Result<DefaultModelUpdateResult, ModelSelectionRejection> {
        let current = self.authoritative_config_active_model();
        let should_write = match intent {
            DefaultModelWriteIntent::Replace => current.as_ref() != Some(target),
            DefaultModelWriteIntent::None => unreachable!("handled above"),
        };
        if !should_write {
            return Ok(match intent {
                DefaultModelWriteIntent::Replace => DefaultModelUpdateResult::verified(
                    target.clone(),
                    self.active_model_state_generation.max(1),
                    "test".to_string(),
                    true,
                ),
                DefaultModelWriteIntent::None => unreachable!("handled above"),
            });
        }

        // Session first for replace (mirrors journal order after prepared).
        if matches!(intent, DefaultModelWriteIntent::Replace)
            && self.test_fail_next_active_model_session_persist
        {
            self.test_fail_next_active_model_session_persist = false;
            return Err(ModelSelectionRejection::failure(
                target,
                "test injected active model session persist failure",
                "model_selection_session_persist_failed",
            ));
        }
        match self.write_active_model_config_for_test(target) {
            Ok(()) => {
                if matches!(intent, DefaultModelWriteIntent::Replace)
                    && let Err(error) = self.session.set_active_model_ref(target.clone())
                {
                    return Err(ModelSelectionRejection::failure(
                        target,
                        &format!("{error:#}"),
                        "effective_default_session_cas_failed",
                    ));
                }
                Ok(DefaultModelUpdateResult::verified(
                    target.clone(),
                    next_active_model_state_generation(self.active_model_state_generation)
                        .expect("model selection rejects an exhausted generation"),
                    "test".to_string(),
                    false,
                ))
            }
            Err(error) => Err(ModelSelectionRejection::failure(
                target,
                &format!("{error:#}"),
                "default_model_write_failed",
            )),
        }
    }

    #[cfg(test)]
    fn write_active_model_config_for_test(
        &mut self,
        active: &crate::config::providers::ActiveModelRef,
    ) -> Result<()> {
        if self.test_fail_next_active_model_config_write {
            self.test_fail_next_active_model_config_write = false;
            anyhow::bail!("test injected active model config write failure");
        }
        if let Some((providers, provider, model)) = self.test_providers_override.as_mut() {
            providers.active_model = Some(active.clone());
            *provider = active.provider.clone();
            *model = active.model.clone();
            return Ok(());
        }
        unreachable!("test config write helper requires an override or injected failure")
    }

    fn persist_active_model_session(
        &mut self,
        selection: &crate::config::providers::ActiveModelRef,
    ) -> Result<()> {
        #[cfg(test)]
        if self.test_fail_next_active_model_session_persist {
            self.test_fail_next_active_model_session_persist = false;
            anyhow::bail!("test injected active model session persist failure");
        }
        self.session.set_active_model_ref(selection.clone())
    }

    async fn record_model_switch_audit(&mut self, audit: crate::session::ModelSwitchAudit<'_>) {
        #[cfg(test)]
        if self.test_fail_next_model_switch_audit_record {
            self.test_fail_next_model_switch_audit_record = false;
            tracing::warn!(
                from_provider = audit.from_provider,
                from_model = audit.from_model,
                to_provider = audit.to_provider,
                to_model = audit.to_model,
                trigger = audit.trigger.as_str(),
                outcome = audit.outcome.as_str(),
                error = audit.error,
                "test injected model switch audit record failure"
            );
            return;
        }

        if let Err(e) = self.session.record_model_switch(audit).await {
            tracing::warn!(
                error = %e,
                from_provider = audit.from_provider,
                from_model = audit.from_model,
                to_provider = audit.to_provider,
                to_model = audit.to_model,
                trigger = audit.trigger.as_str(),
                outcome = audit.outcome.as_str(),
                "failed to record model switch audit event"
            );
        }
    }

    async fn emit_active_model_state(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        self.emit_active_model_state_with_default(tx, None).await;
    }

    pub(in crate::engine::driver) async fn emit_active_model_state_correction(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        self.emit_active_model_state_for_generation(tx, None).await;
    }

    async fn emit_active_model_state_with_default(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
        default_selection_override: Option<crate::config::providers::ActiveModelRef>,
    ) {
        let Some(generation) =
            next_active_model_state_generation(self.active_model_state_generation)
        else {
            tracing::error!(
                session_id = %self.session.id,
                "cannot emit active model state: generation space is exhausted"
            );
            return;
        };
        self.active_model_state_generation = generation;
        self.emit_active_model_state_for_generation(tx, default_selection_override)
            .await;
    }

    async fn emit_active_model_state_for_generation(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        default_selection_override: Option<crate::config::providers::ActiveModelRef>,
    ) {
        // A config-watch refresh trails a successful default write. Use the
        // just-written value for this state emission so clients never briefly
        // render a false divergence before the terminal result arrives.
        let default_selection =
            default_selection_override.or_else(|| self.live_config_active_model());
        let selection = self.session.active_model_ref().unwrap_or_else(|| {
            crate::config::providers::ActiveModelRef {
                provider: self.stack[0].agent.model.provider_id().to_string(),
                model: self.stack[0].agent.model.model_id_ref().to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }
        });
        let diverged = default_selection.as_ref() != Some(&selection);
        let _ = tx
            .send(TurnEvent::ActiveModelState {
                selection,
                default_selection,
                diverged,
                generation: self.active_model_state_generation,
            })
            .await;
    }

    /// Swap the root-frame agent to `name` in place, preserving the root
    /// history so the new primary continues the same conversation. Only the
    /// root frame is swapped, and only at idle (the control boundary) — a
    /// deeper interactive subagent frame is never touched. No-op when an
    /// interactive subagent holds the foreground or the agent is already
    /// active. The new agent is built through [`crate::engine::builtin::load`]
    /// so a user override of `Plan`/`Build` takes effect.
    ///
    /// Before re-rooting, the outgoing primary's abandoned (non-steering)
    /// user-invoked skill pairs are stripped from history so a skill the
    /// previous primary declined to follow does not govern the new primary
    /// (implementation note).
    ///
    /// The `/plan`/`/build` (and `/agent`, `Shift+Tab`) swaps route here at
    /// **idle** and return to idle without a turn — the new primary's first
    /// turn is driven by the user's *next* message, which is already
    /// actionable, so there is no separate kickoff to inject for those paths.
    pub(in crate::engine::driver) async fn swap_primary(
        &mut self,
        name: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        self.swap_primary_with_context(name, PrimarySwapContext::swap_command(), tx)
            .await;
    }

    /// [`Self::swap_primary`] plus the export-audit `primary_swap` context: the
    /// trigger and optional wire-vs-user `display`/`kickoff` pair (GOALS §14).
    /// The control-swap entry point passes
    /// [`PrimarySwapContext::swap_command`] (no kickoff). The `primary_swap`
    /// timeline event is recorded only on a successful re-root, so a failed
    /// agent load never records a phantom swap.
    pub(in crate::engine::driver) async fn swap_primary_with_context(
        &mut self,
        name: &str,
        swap_ctx: PrimarySwapContext<'_>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if self.stack.len() != 1 {
            tracing::warn!(
                requested = %name,
                "primary swap ignored: an interactive subagent holds the foreground"
            );
            return false;
        }
        if self.stack[0].agent.name == name {
            return true;
        }
        match crate::engine::builtin::load(name, &self.spawn_args(true)) {
            Ok(agent) => {
                // An abandoned skill the outgoing primary declined to follow
                // must not cross the swap as authoritative instructions for
                // the new primary (implementation note).
                // Strip the outgoing primary's non-steering skill pairs before
                // re-rooting; a future intentionally-steering skill opts out
                // via `intentional_steer` and survives.
                let outgoing = self.stack[0].agent.name.clone();
                self.strip_abandoned_skill_pairs(&outgoing).await;
                // Per-call tool-call ownership (`cross-agent-tool-call-
                // annotation.md`): attribute every not-yet-attributed tool call
                // now in the root history to the OUTGOING agent before re-
                // rooting. Runs AFTER the skill-pair strip so an abandoned skill
                // call (already removed) is never attributed. Swaps fire at idle,
                // so the just-finished run's calls are all present — attribution
                // is exact across any number of swaps. Existing entries are never
                // overwritten (a re-swap doesn't reattribute earlier calls).
                self.record_tool_call_ownership(&outgoing);
                let outgoing_write_capable =
                    crate::engine::builtin::is_write_capable(&self.stack[0].agent);
                let incoming_write_capable = crate::engine::builtin::is_write_capable(&agent);
                if outgoing_write_capable {
                    let lock_result = if incoming_write_capable {
                        self.locks
                            .transfer_agent_locks(&outgoing, &agent.name, self.session.id)
                            .await
                            .map(|_| ())
                    } else {
                        self.locks
                            .suspend_agent(&outgoing, self.session.id)
                            .await
                            .map(|_| ())
                    };
                    if let Err(e) = lock_result {
                        tracing::warn!(
                            error = ?e,
                            from = %outgoing,
                            to = %agent.name,
                            "primary swap failed during lock ownership update"
                        );
                        return false;
                    }
                }
                // Deferred agent-swap identity marker (`agent-swap-
                // identity-marker.md`): a `swap_command` swap leaves no boundary
                // entry on the wire, so record the previously-effective agent now
                // for injection on the user's next message. Capture the outgoing
                // agent only at the FIRST swap since the last message — never
                // overwrite it on an intermediate hop — so a multi-swap run
                // coalesces to one marker naming previously-effective → final.
                if swap_ctx.trigger == SWAP_TRIGGER_COMMAND
                    && self.pending_swap_marker_from.is_none()
                {
                    self.pending_swap_marker_from = Some(outgoing.clone());
                }
                self.stack[0].agent = Arc::new(agent);
                self.stack[0].queue_target =
                    crate::engine::message::QueueTarget::root(name.to_string());
                // The job authority's fork context is rooted on the old
                // agent; rebind it so any future loop fork runs on the new
                // primary's model/tool surface (single-authority rule).
                self.schedule.set_agent(self.stack[0].agent.clone());
                self.publish_active_tool_names().await;
                tracing::info!(agent = %name, "primary agent swapped");
                // `primary_swap` timeline event (export-audit fidelity):
                // from/to + trigger + both halves of the wire-vs-user split.
                if let Err(e) = self
                    .session
                    .record_primary_swap(
                        &outgoing,
                        name,
                        swap_ctx.trigger,
                        swap_ctx.display,
                        swap_ctx.kickoff,
                    )
                    .await
                {
                    tracing::warn!(error = %e, "record primary_swap event failed");
                }
                // Tell the client chrome's active-agent slot about the new
                // primary, then refresh the prunable projection.
                let _ = tx
                    .send(TurnEvent::PrimarySwapped {
                        name: name.to_string(),
                    })
                    .await;
                let _ = tx
                    .send(TurnEvent::ForegroundInputTarget {
                        target: self.active_queue_target(),
                    })
                    .await;
                self.emit_context_projection(tx).await;
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, requested = %name, "primary swap failed to load agent");
                false
            }
        }
    }

    /// Annotate, in the wire history, every historical tool call whose tool the
    /// **final** (now-active) agent lacks
    /// (implementation note). Consumed at the user's
    /// next message — the same coalesce-and-defer boundary as
    /// [`Self::inject_pending_swap_marker`] — so the cached prefix stays
    /// byte-stable until the message is actually sent, and absence is evaluated
    /// once against the final agent's authoritative tool set
    /// ([`crate::engine::tool::ToolBox::get`], role-driven, not name-bound).
    ///
    /// For each matching call the note is prepended to its `tool_result`
    /// content (what the model reads as the call's outcome), e.g.
    /// `` [Called by `Build`, which had the `edit` tool. You (`Plan`) do not ``
    /// `` have this tool.] ``. Calls for tools the final agent still has are
    /// left unchanged; `task` (subagent) calls follow the same rule. Wire-only
    /// (GOALS §14) — the user transcript is untouched.
    ///
    /// Idempotent: an already-annotated result (carrying [`CROSS_AGENT_NOTE`])
    /// is skipped, so re-evaluation on a later message never double-stamps, and
    /// a re-swap that restores the tool never strips an earlier note (it stays
    /// historically accurate). Only meaningful at the root frame.
    pub(in crate::engine::driver) fn annotate_absent_tool_calls(&mut self) {
        use crate::engine::message::AssistantContent;
        use rig::message::UserContent;
        if self.tool_call_owner.is_empty() {
            return;
        }
        let final_agent = self.active_agent().to_string();
        let root = &self.stack[0];
        // call_id → tool name, for every tool call in the root history, plus
        // the set of tool names absent from the final agent's authoritative
        // surface (`ToolBox::get`, role-driven). Built up front so the history
        // mutation below borrows nothing else from `self`.
        let mut absent_call: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for msg in &root.history {
            if let Message::Assistant { content, .. } = msg {
                for c in content.iter() {
                    if let AssistantContent::ToolCall(tc) = c
                        && root.agent.tools.get(&tc.function.name).is_none()
                    {
                        absent_call.insert(tc.id.to_string(), tc.function.name.clone());
                    }
                }
            }
        }
        if absent_call.is_empty() {
            return;
        }
        let owners = &self.tool_call_owner;
        for msg in &mut self.stack[0].history {
            let Message::User { content } = msg else {
                continue;
            };
            // Skip well-formed messages with no annotatable tool_result fast.
            if !content.iter().any(
                |p| matches!(p, UserContent::ToolResult(tr) if absent_call.contains_key(tr.call.as_str())),
            ) {
                continue;
            }
            let parts: Vec<UserContent> = content
                .iter()
                .map(|part| match part {
                    UserContent::ToolResult(tr) => {
                        let (Some(tool), Some(owner)) = (
                            absent_call.get(tr.call.as_str()),
                            owners.get(tr.call.as_str()),
                        ) else {
                            return part.clone();
                        };
                        let note = format!(
                            "[Called by `{owner}`, which had the `{tool}` tool. You \
                             (`{final_agent}`) do not have this tool.] "
                        );
                        UserContent::ToolResult(prepend_tool_result_note(tr, &note))
                    }
                    other => other.clone(),
                })
                .collect();
            *content = parts;
        }
    }
}

#[cfg(test)]
mod structured_paste_generation_tests {
    use super::next_active_model_state_generation;

    #[test]
    fn paste_fence_model_generation_checked_overflow() {
        assert_eq!(
            next_active_model_state_generation(u64::MAX - 1),
            Some(u64::MAX)
        );
        assert_eq!(next_active_model_state_generation(u64::MAX), None);
    }
}

#[cfg(test)]
mod default_model_commit_tests {
    use super::*;

    fn selection(provider: &str, model: &str) -> crate::config::providers::ActiveModelRef {
        crate::config::providers::ActiveModelRef {
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }
    }

    #[test]
    fn verified_outcome_carries_scope_and_selection() {
        let target = selection("provider-b", "model-b");
        let result =
            DefaultModelUpdateResult::verified(target.clone(), 3, "user".to_string(), false);
        match result.outcome {
            crate::daemon::proto::DefaultModelUpdateOutcome::Verified {
                selection,
                generation,
                scope_label,
                unchanged,
            } => {
                assert_eq!(selection, target);
                assert_eq!(generation, 3);
                assert_eq!(scope_label, "user");
                assert!(!unchanged);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        assert_eq!(result.authoritative_selection.as_ref(), Some(&target));
    }
}
