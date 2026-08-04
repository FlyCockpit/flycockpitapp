use super::*;

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

    fn write_failed(
        target: &crate::config::providers::ActiveModelRef,
        error: &anyhow::Error,
        authoritative_selection: Option<crate::config::providers::ActiveModelRef>,
    ) -> Self {
        Self {
            outcome: crate::daemon::proto::DefaultModelUpdateOutcome::Failed {
                user_message: format!(
                    "Using `{}/{}` for this session, but could not save it as the default — {error:#}.",
                    target.provider, target.model
                ),
                diagnostic_code: "default_model_write_failed".to_string(),
            },
            authoritative_selection,
        }
    }

    fn from_prepared_commit(
        target: &crate::config::providers::ActiveModelRef,
        intent: DefaultModelWriteIntent,
        authoritative_before_commit: Option<crate::config::providers::ActiveModelRef>,
        committed: Result<crate::config::providers::ActiveModelWriteResult>,
    ) -> Self {
        match committed {
            Ok(result) => Self {
                outcome: match intent {
                    DefaultModelWriteIntent::InitializeIfMissing if !result.wrote => {
                        crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested
                    }
                    DefaultModelWriteIntent::Replace
                    | DefaultModelWriteIntent::InitializeIfMissing => {
                        crate::daemon::proto::DefaultModelUpdateOutcome::Saved
                    }
                    DefaultModelWriteIntent::None => unreachable!("handled during prepare"),
                },
                authoritative_selection: result.authoritative_selection,
            },
            Err(error) => Self::write_failed(target, &error, authoritative_before_commit),
        }
    }
}

enum PreparedDefaultModelUpdate {
    Immediate(DefaultModelUpdateResult),
    Production {
        write: Box<crate::config::providers::PreparedActiveModelWrite>,
        intent: DefaultModelWriteIntent,
        authoritative_before_commit: Option<crate::config::providers::ActiveModelRef>,
    },
    #[cfg(test)]
    Test(DefaultModelWriteIntent),
}

#[derive(Clone, Copy)]
pub(super) enum DefaultModelWriteIntent {
    None,
    Replace,
    InitializeIfMissing,
}

impl DefaultModelWriteIntent {
    pub(super) fn from_flags(
        persist_as_default: bool,
        initialize_default_if_missing: bool,
    ) -> Self {
        if persist_as_default {
            Self::Replace
        } else if initialize_default_if_missing {
            Self::InitializeIfMissing
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
}

impl ModelSelectionRejection {
    fn deadline() -> Self {
        Self {
            user_message:
                "Model selection timed out before it could be committed; retry from /model."
                    .to_string(),
            diagnostic_code: "model_selection_deadline_exceeded",
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
        let old_llm_mode = self.stack[root_idx].agent.llm_mode;
        let old_prompt_cache_retention_preference = self.prompt_cache_retention_preference;
        self.prompt_cache_retention_preference = target.prompt_cache_retention;
        if current.provider_id() == provider
            && current.model_id_ref() == model
            && old_session_selection.as_ref() == Some(&target)
        {
            let prepared_default = match self
                .prepare_default_model(&target, default_write, deadline)
                .await
            {
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
            let default_update = self.commit_prepared_default_model(&target, prepared_default);
            if matches!(
                default_update.outcome,
                crate::daemon::proto::DefaultModelUpdateOutcome::Saved
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
            let saved_default = matches!(
                &default_update.outcome,
                crate::daemon::proto::DefaultModelUpdateOutcome::Saved
            )
            .then(|| target.clone())
            .or_else(|| default_update.authoritative_selection.clone());
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
        let llm_mode = self.effective_llm_mode_for(provider, model);
        let rebuilt =
            match self.try_rebuild_frame_with_model(root_idx, new_model.clone(), llm_mode, &target)
            {
                Ok(agent) => Arc::new(agent),
                Err(_) if root_idx == 0 => {
                    Arc::new(self.rebuild_frame_with_model(root_idx, new_model, llm_mode, &target))
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
        let prepared_default = match self
            .prepare_default_model(&target, default_write, deadline)
            .await
        {
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
        if let Err(e) = self.persist_active_model_session(&target) {
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
        let default_update = self.commit_prepared_default_model(&target, prepared_default);
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
        if old_llm_mode != llm_mode {
            let _ = tx.send(TurnEvent::LlmModeChanged { mode: llm_mode }).await;
        }
        tracing::info!(provider, model, "active model switched live");
        // The model changed, so the prefix cache key changes — refresh the
        // prunable projection the chrome shows (cache-cold reflects the bust).
        self.emit_context_projection(tx).await;
        let saved_default = matches!(
            &default_update.outcome,
            crate::daemon::proto::DefaultModelUpdateOutcome::Saved
        )
        .then(|| target.clone())
        .or_else(|| default_update.authoritative_selection.clone());
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
        let terminal_default_selection = default_update.authoritative_selection.or_else(|| {
            matches!(
                &default_update.outcome,
                crate::daemon::proto::DefaultModelUpdateOutcome::Saved
            )
            .then(|| target.clone())
            .or_else(|| self.live_config_active_model())
        });
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
                        active_state: crate::daemon::proto::ModelSelectionActiveState {
                            selection: target.clone(),
                            default_selection: terminal_default_selection,
                            diverged: terminal_diverged,
                            generation: self.active_model_state_generation,
                        },
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
        let mut built = crate::engine::model::Model::for_provider_with_env(
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

    fn authoritative_config_active_model(
        &self,
    ) -> Option<crate::config::providers::ActiveModelRef> {
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            return providers.active_model.clone();
        }
        crate::daemon::config_source::load_effective_providers_for_atomic_mutation(&self.cwd)
            .active_model
    }

    async fn prepare_default_model(
        &mut self,
        target: &crate::config::providers::ActiveModelRef,
        intent: DefaultModelWriteIntent,
        deadline: Option<std::time::Instant>,
    ) -> std::result::Result<PreparedDefaultModelUpdate, ModelSelectionRejection> {
        if matches!(intent, DefaultModelWriteIntent::None) {
            return Ok(PreparedDefaultModelUpdate::Immediate(
                DefaultModelUpdateResult {
                    outcome: crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
                    authoritative_selection: self.live_config_active_model(),
                },
            ));
        }

        #[cfg(test)]
        if self.test_providers_override.is_some() || self.test_fail_next_active_model_config_write {
            return Ok(PreparedDefaultModelUpdate::Test(intent));
        }

        // Acquire the cross-process lock, resolve the effective layered
        // default, serialize, and fsync a private temp file before terminal
        // ownership is claimed. Lock acquisition polls a cancellation flag:
        // after a deadline we cancel and join the blocking task before
        // returning, so timed-out attempts cannot remain queued and later
        // monopolize the global config lock.
        let cwd = self.cwd.clone();
        let target_for_write = target.clone();
        let trust_policy = crate::config::trust::current_workspace_trust_policy();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let prepare_cancelled = std::sync::Arc::clone(&cancelled);
        let mut prepare = tokio::task::spawn_blocking(move || {
            let write = || {
                let path = crate::config::dirs::most_specific_config_write_target(&cwd)
                    .context("no cockpit config found — run `/settings` to create one")?;
                let mode = match intent {
                    DefaultModelWriteIntent::Replace => {
                        crate::config::providers::ActiveModelWriteMode::Replace
                    }
                    DefaultModelWriteIntent::InitializeIfMissing => {
                        crate::config::providers::ActiveModelWriteMode::InitializeIfMissing
                    }
                    DefaultModelWriteIntent::None => unreachable!("handled above"),
                };
                crate::config::providers::ConfigDoc::prepare_effective_active_model_write_cancellable(
                    &cwd,
                    &path,
                    &target_for_write,
                    mode,
                    &prepare_cancelled,
                )
            };
            match trust_policy {
                Some(policy) => crate::config::trust::with_workspace_trust_policy(policy, write),
                None => write(),
            }
        });
        let prepared = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut prepare)
                .await
            {
                Ok(result) => result,
                Err(_) => {
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                    // `spawn_blocking` tasks are not cancelled when their
                    // join handle is dropped. Await the cooperatively
                    // cancelled waiter so no orphan can acquire this lock
                    // after the deadline. Any prepared plan that won the
                    // boundary race is dropped here without committing.
                    if let Err(error) = prepare.await {
                        tracing::warn!(
                            %error,
                            "joining cancelled active-model config mutation preparation"
                        );
                    }
                    return Err(ModelSelectionRejection::deadline());
                }
            }
        } else {
            prepare.await
        };
        let prepared = match prepared {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!(
                "joining active-model config mutation preparation: {error}"
            )),
        };

        Ok(match prepared {
            Ok(write) => {
                let authoritative_before_commit =
                    write.authoritative_selection_before_commit().cloned();
                PreparedDefaultModelUpdate::Production {
                    write: Box::new(write),
                    intent,
                    authoritative_before_commit,
                }
            }
            Err(error) => {
                PreparedDefaultModelUpdate::Immediate(DefaultModelUpdateResult::write_failed(
                    target,
                    &error,
                    self.authoritative_config_active_model(),
                ))
            }
        })
    }

    fn commit_prepared_default_model(
        &mut self,
        target: &crate::config::providers::ActiveModelRef,
        prepared: PreparedDefaultModelUpdate,
    ) -> DefaultModelUpdateResult {
        match prepared {
            PreparedDefaultModelUpdate::Immediate(result) => result,
            PreparedDefaultModelUpdate::Production {
                write,
                intent,
                authoritative_before_commit,
            } => DefaultModelUpdateResult::from_prepared_commit(
                target,
                intent,
                authoritative_before_commit,
                (*write).commit(),
            ),
            #[cfg(test)]
            PreparedDefaultModelUpdate::Test(intent) => {
                self.update_default_model_for_test(target, intent)
            }
        }
    }

    #[cfg(test)]
    fn update_default_model_for_test(
        &mut self,
        target: &crate::config::providers::ActiveModelRef,
        intent: DefaultModelWriteIntent,
    ) -> DefaultModelUpdateResult {
        let current = self.authoritative_config_active_model();
        let should_write = match intent {
            DefaultModelWriteIntent::Replace => current.as_ref() != Some(target),
            DefaultModelWriteIntent::InitializeIfMissing => current.is_none(),
            DefaultModelWriteIntent::None => unreachable!("handled above"),
        };
        if !should_write {
            return DefaultModelUpdateResult {
                outcome: match intent {
                    DefaultModelWriteIntent::Replace => {
                        crate::daemon::proto::DefaultModelUpdateOutcome::Saved
                    }
                    DefaultModelWriteIntent::InitializeIfMissing => {
                        crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested
                    }
                    DefaultModelWriteIntent::None => unreachable!("handled above"),
                },
                authoritative_selection: current,
            };
        }

        match self.write_active_model_config_for_test(target) {
            Ok(()) => DefaultModelUpdateResult {
                outcome: crate::daemon::proto::DefaultModelUpdateOutcome::Saved,
                authoritative_selection: Some(target.clone()),
            },
            Err(error) => DefaultModelUpdateResult::write_failed(target, &error, current),
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
        self.active_model_state_generation = self.active_model_state_generation.saturating_add(1);
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
    /// The imperative-kickoff contract (begin work on the first turn, tool
    /// call not narration) attaches only to the [`Self::apply_handoff`] path:
    /// a `handoff` fires **mid-turn**, so the swapped-in primary's first input
    /// is the synthesized `handoff` tool_result, which `apply_handoff` builds
    /// as the kickoff. The `/plan`/`/build`/`/swarm` (and `/agent`,
    /// `Shift+Tab`) swaps route here at **idle** and return to idle without a
    /// turn — the new primary's first turn is driven by the user's *next*
    /// message, which is already actionable, so there is no separate kickoff
    /// to inject for those paths.
    pub(in crate::engine::driver) async fn swap_primary(
        &mut self,
        name: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        self.swap_primary_with_context(name, PrimarySwapContext::swap_command(), tx)
            .await;
    }

    /// [`Self::swap_primary`] plus the export-audit `primary_swap` context: the
    /// trigger and (for the `handoff` path) the wire-vs-user `display`/`kickoff`
    /// pair (GOALS §14). The control-swap entry point passes
    /// [`PrimarySwapContext::swap_command`] (no kickoff); [`Self::apply_handoff`]
    /// passes the handoff display + kickoff. The `primary_swap` timeline event
    /// is recorded only on a successful re-root, so a failed agent load never
    /// records a phantom swap.
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
                // The `handoff` path injects its own kickoff and sets nothing.
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

    /// Build the imperative kickoff the swapped-in primary takes its first
    /// turn on after a `handoff` (implementation note).
    /// It restates the user's **salient originating request verbatim** (the
    /// most recent user turn in the shared root history — not the outgoing
    /// primary's paraphrase) and instructs the new primary to begin now with a
    /// tool call rather than a description of intent. This replaces the bare
    /// `` "Handed off to `{target}`." `` ack — a weaker model reads that ack as
    /// something to narrate and emits no tool call, terminating the loop.
    /// Token-efficient (§10): the restated request plus one imperative line,
    /// no boilerplate. Falls back to the imperative alone when no user turn is
    /// present (defensive — a handoff always follows a user request).
    pub(in crate::engine::driver) fn handoff_kickoff(&self) -> String {
        let request = crate::engine::predict::turns_from_messages(&self.stack[0].history)
            .pop()
            .map(|t| t.user)
            .filter(|u| !u.trim().is_empty());
        let imperative = "Begin now. Act on this request directly — your first action must be a \
                          tool call, not a description of what you intend to do.";
        match request {
            Some(req) => format!("User's request:\n{}\n\n{imperative}", req.trim()),
            None => imperative.to_string(),
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
        use crate::engine::message::{AssistantContent, OneOrMany};
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
                        absent_call.insert(tc.id.clone(), tc.function.name.clone());
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
                |p| matches!(p, UserContent::ToolResult(tr) if absent_call.contains_key(&tr.id)),
            ) {
                continue;
            }
            let parts: Vec<UserContent> = content
                .iter()
                .map(|part| match part {
                    UserContent::ToolResult(tr) => {
                        let (Some(tool), Some(owner)) =
                            (absent_call.get(&tr.id), owners.get(&tr.id))
                        else {
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
            if let Ok(rebuilt) = OneOrMany::many(parts) {
                *content = rebuilt;
            }
        }
    }

    /// Apply an `Auto` → `Plan`/`Build` handoff at the idle boundary and
    /// return the `handoff` tool_result the swapped-in primary takes its next
    /// turn on. Emits the `handoff` tool_call timeline events, persists the
    /// new active agent (so a resume restarts on it), then swaps the
    /// root-frame primary in place through [`Self::swap_primary`] — the same
    /// machinery `/plan`/`/build` use, which preserves the root history so the
    /// chosen primary continues this same conversation. Sole owner of the
    /// handoff side effects so the live turn loop and the regression test
    /// drive byte-identical behavior. The tool_result is built **before** the
    /// swap so it lands in the shared root history `swap_primary` preserves.
    ///
    /// The tool_result the swapped-in primary takes its first turn on is the
    /// **imperative kickoff** ([`Self::handoff_kickoff`]) — the user's salient
    /// originating request restated verbatim plus a begin-now instruction —
    /// **not** a bare ack. A bare ack made weaker models narrate and emit no
    /// tool call, terminating the loop (`handoff-kickoff-and-skill-
    /// leak.md`). The **user-facing** timeline still shows the terse
    /// `` "Handed off to `{target}`." `` row (wire-vs-user split, GOALS §14):
    /// the model sees the kickoff (wire), the user sees the clean ack.
    pub(in crate::engine::driver) async fn apply_handoff(
        &mut self,
        target: &str,
        task_call_id: String,
        task_function_call_id: Option<String>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Message {
        let agent_name = self.stack.last().unwrap().agent.name.clone();
        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                args: serde_json::json!({ "target": target }),
            })
            .await;
        // User-facing timeline row: terse ack. The model-facing tool_result is
        // the imperative kickoff (wire-vs-user split, GOALS §14).
        let display = format!("Handed off to `{target}`.");
        let _ = tx
            .send(TurnEvent::ToolEnd {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                output: display.clone(),
                truncated: false,
                seq: None,
                // The hint layer is `bash`-only.
                hint: None,
            })
            .await;
        // Build the kickoff from the user's originating request BEFORE the swap
        // strips any abandoned skill pair — `turns_from_messages` reads the
        // last plain user turn (the skill body is a tool-result round it skips),
        // so the restated request is the user's, not the skill's.
        let kickoff = self.handoff_kickoff();
        let next_prompt =
            Message::tool_result_with_call_id(task_call_id, task_function_call_id, kickoff.clone());
        // The `primary_swap` event records BOTH the user-facing `display` and
        // the model-facing wire `kickoff` (GOALS §14) with trigger `handoff`.
        let swapped = self
            .swap_primary_with_context(target, PrimarySwapContext::handoff(&display, &kickoff), tx)
            .await;
        if swapped && let Err(e) = self.session.set_active_agent(target) {
            tracing::warn!(error = %e, "set_active_agent on handoff failed");
        }
        next_prompt
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
    fn failed_prepared_commit_retains_old_authoritative_default_and_divergence() {
        let old = selection("provider-a", "model-a");
        let target = selection("provider-b", "model-b");

        let result = DefaultModelUpdateResult::from_prepared_commit(
            &target,
            DefaultModelWriteIntent::Replace,
            Some(old.clone()),
            Err(anyhow::anyhow!("injected atomic replacement failure")),
        );

        assert!(matches!(
            result.outcome,
            crate::daemon::proto::DefaultModelUpdateOutcome::Failed { .. }
        ));
        assert_eq!(result.authoritative_selection, Some(old));
        assert_ne!(
            result.authoritative_selection.as_ref(),
            Some(&target),
            "the terminal active state must remain diverged after commit failure"
        );
    }
}
