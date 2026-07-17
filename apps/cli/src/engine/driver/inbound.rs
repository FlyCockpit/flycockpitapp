use super::*;

/// Resolve where to persist an edited injection check-prompt: the project
/// `.cockpit/` layer for `cwd` when one already exists (so the override is
/// project-scoped where the project already carries config), else the
/// global home config. Returns the target path plus a human scope label.
pub(in crate::engine::driver) fn injection_check_prompt_target(
    cwd: &std::path::Path,
) -> Result<(std::path::PathBuf, &'static str)> {
    use crate::config::dirs::{ConfigDirKind, discover_config_dirs};
    if let Some(dir) = discover_config_dirs(cwd)
        .into_iter()
        .find(|d| matches!(d.kind, ConfigDirKind::Project))
    {
        return Ok((dir.path.join(crate::config::dirs::CONFIG_FILE), "project"));
    }
    Ok((global_extended_config_path()?, "global"))
}

/// Wrap `user_text` with the `[time: ...]` prelude when the
/// session's interval has elapsed. Side-effect: stamps the
/// session's last-prelude timestamp on success. No-op when the
/// interval hasn't elapsed.
impl Driver {
    pub(in crate::engine::driver) fn with_time_prelude(&self, user_text: String) -> String {
        match self
            .session
            .take_time_prelude(self.time_injection_interval_minutes)
        {
            Some(prelude) => format!("{prelude}\n\n{user_text}"),
            None => user_text,
        }
    }

    /// Skills auto-selection seam (GOALS §5). Loads the layered config,
    /// consults the cheap utility model with the skill catalog + the recent
    /// conversation window (the same last-3-turn shape `predict` uses), and
    /// — if any skills are selected — returns `user_text` with each chosen
    /// skill's (`!`-processed, scrubbed) body prepended in relevance order
    /// so the main agent's first inference carries them. Selection is capped
    /// in count and total token budget. Returns `user_text` unchanged when
    /// no skill is chosen.
    ///
    /// Graceful degradation: an unset `utility_model` skips the pass
    /// (logged at most once) and returns `user_text` untouched — no
    /// error, no main-model fallback. The cheap model only ever sees the
    /// `(name, description)` catalog (token economy, GOALS §10).
    pub(in crate::engine::driver) async fn maybe_inject_skill(
        &mut self,
        user_text: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> String {
        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);

        if extended.skill_injection_model_ref().is_none() {
            if !self.skills_no_utility_model_logged {
                self.skills_no_utility_model_logged = true;
                tracing::info!("skills auto-selection skipped: no `utility_model` configured");
            }
            return user_text.to_string();
        }

        // Feed the selector the same window `predict` uses: the recent
        // turns (user input + agent final response, no tool calls). The
        // current user message isn't in history yet (it's pushed inside
        // `turn()`), so append it as the latest open turn before windowing.
        let mut turns = crate::engine::predict::turns_from_messages(&self.stack[0].history);
        turns.push(crate::engine::predict::PredictionTurn {
            user: user_text.to_string(),
            agent: String::new(),
        });

        let (selection, diagnostics) = crate::skills::auto_select::select_with_diagnostics(
            &self.cwd,
            &extended,
            &providers,
            self.redact.clone(),
            self.session.trusted_only_flag(),
            &turns,
            &self.auto_injected_skills,
        )
        .await;
        if !diagnostics.is_empty() {
            let data = serde_json::json!({ "rejections": diagnostics.rejections });
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SkillAutoSelect,
                Some(&self.stack[0].agent.name),
                None,
                &data,
            ) {
                tracing::warn!(error = %e, "recording skill auto-select diagnostics failed");
            }
        }

        match selection {
            crate::skills::auto_select::Selection::Skills(skills) => {
                let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
                tracing::debug!(skills = ?names, "skills auto-selection injected skill bodies");
                for skill in &skills {
                    // Record the auto-injected body in the seedable set so a
                    // later `task.skill_seed` naming this skill passes host
                    // validation (implementation note).
                    self.record_active_skill(&skill.name, &skill.body);
                    // Record it in the auto-injection suppression set so it is
                    // not re-injected later this session (once-per-session,
                    // implementation note change 4).
                    // Recorded only on actual injection, not on vote/match —
                    // a voted-then-dropped skill stays eligible for a later
                    // turn when it finally fits.
                    self.auto_injected_skills.insert(skill.name.clone());
                    // Surface the injection in the transcript as a distinct
                    // `/{name} · injected by agent` row, in injection order,
                    // ahead of the user's message (`auto-injected-skill-
                    // transcript-visibility.md`). UI-only — the wire still
                    // carries the body folded into the user message below
                    // (wire-vs-user split, GOALS §14).
                    let _ = tx
                        .send(TurnEvent::SkillAutoInjected {
                            name: skill.name.clone(),
                            // Display-only / off-wire (GOALS §14): the reason
                            // (model clause or keyword-overlap fallback) rides
                            // the user-facing row, never the folded body.
                            reason: skill.reason.clone(),
                        })
                        .await;
                }
                // Fold every surviving body in relevance order ahead of the
                // user's message — the wire half of the split (the model still
                // sees the bodies; the `SkillAutoInjected` rows above are the
                // user-facing half).
                Self::fold_injected_skills(&skills, user_text)
            }
            crate::skills::auto_select::Selection::None => user_text.to_string(),
        }
    }

    /// Inbound utility-model translation (implementation note):
    /// translate `text` from the user's language into the model's language.
    /// Returns the text unchanged when the feature is inactive (languages
    /// unset/equal) or the utility model is unset/unavailable/erroring —
    /// degrade, never block the turn. Called between the injection scan
    /// (which sees the raw text) and outbound redaction.
    pub(in crate::engine::driver) async fn translate_inbound(&self, text: &str) -> String {
        match crate::engine::translate::load_if_active(&self.cwd) {
            Some((extended, providers)) => {
                crate::engine::translate::inbound(
                    text,
                    &extended,
                    &providers,
                    self.redact.clone(),
                    self.session.trusted_only_flag(),
                )
                .await
            }
            None => text.to_string(),
        }
    }

    /// Prompt-injection guard (GOALS §4i). Scans the **raw** user text
    /// (before redaction) through the history-free, nonce-wrapped
    /// injection check ([`crate::engine::injection_check`]) and returns
    /// whether the prompt may proceed. Two-part so the check can run
    /// concurrently with the request-preflight rewrite
    /// (implementation note): [`Self::injection_check_only`] runs
    /// the classification, [`Self::apply_injection_outcome`] applies the
    /// (self-mutating) verdict + override UX.
    ///
    /// Run **only** the prompt-injection classification on the raw text,
    /// without any self-mutating override UX. Returns `None` when scanning
    /// is disabled (`threshold == Off`), else the configured threshold +
    /// the [`CheckOutcome`]. Split out from [`Self::injection_guard_allows`]
    /// so the check can run **concurrently** with the request-preflight
    /// rewrite (both consume the same raw text — implementation note).
    pub(in crate::engine::driver) async fn injection_check_only(
        &self,
        raw_text: &str,
    ) -> Option<(
        crate::config::extended::InjectionThreshold,
        crate::engine::injection_check::CheckOutcome,
    )> {
        use crate::config::extended::{InjectionThreshold, resolve_injection_guard};
        use crate::engine::injection_check::check;

        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);
        let guard = resolve_injection_guard(&self.cwd);
        if guard.threshold == InjectionThreshold::Off {
            return None; // scanning disabled
        }
        // The guard's own model override falls back to the utility model.
        let model_ref = extended.guard_model_ref();
        let outcome = check(
            model_ref,
            &providers,
            self.redact.clone(),
            self.session.trusted_only_flag(),
            &guard.check_prompt,
            raw_text,
        )
        .await;
        Some((guard.threshold, outcome))
    }

    /// The effective request-preflight enabled state: the session-only
    /// `/preflight` override ([`Self::preflight_override`]) when set, else
    /// the layered `preflight.enabled` config (implementation note).
    pub(in crate::engine::driver) fn preflight_enabled(&self) -> bool {
        self.preflight_override
            .unwrap_or_else(|| crate::config::extended::resolve_preflight(&self.cwd).enabled)
    }

    /// Whether request preflight will *actually run* for `text` — enabled AND
    /// not a `should_skip` no-op (trivial / bare ack / leading `/`). Drives the
    /// submit-time `PreflightStarted` in-progress signal: only an actually-
    /// running preflight adds the animated `Preflight…` indicator
    /// (implementation note).
    pub(in crate::engine::driver) fn preflight_will_run(&self, text: &str) -> bool {
        self.preflight_enabled() && !crate::engine::preflight::should_skip(text)
    }

    /// Raise the false-positive override prompt for a blocked prompt and
    /// act on the user's choice. Returns whether the prompt may proceed.
    ///
    /// Headless (no interactive client that can answer) → block stands
    /// (`false`): there is no human to override, and silently sending a
    /// high-risk prompt would defeat the guard. A dismissal reads the same.
    pub(in crate::engine::driver) async fn injection_override(
        &mut self,
        rating: crate::config::extended::InjectionThreshold,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        if !self.interrupts.is_interactive_attached() {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "prompt-injection guard blocked this prompt (rated `{}`); no interactive \
                         client to confirm an override — dropped",
                        rating.as_str()
                    ),
                })
                .await;
            return Ok(false);
        }

        let agent = self.active_agent().to_string();
        let description = format!(
            "Prompt-injection guard rated this prompt `{}` (at or above your block threshold). \
             This may be a false positive. How do you want to proceed?",
            rating.as_str()
        );
        let question = InterruptQuestion::Single {
            prompt: "Allow this blocked prompt?".to_string(),
            options: vec![
                InterruptOption {
                    id: ID_INJECTION_SEND_ONCE.to_string(),
                    label: "Approve & send this prompt once".to_string(),
                    description: Some("does not change any setting".to_string()),
                    secondary: false,
                },
                InterruptOption {
                    id: ID_INJECTION_LOWER.to_string(),
                    label: "Approve & lower the block threshold".to_string(),
                    description: Some("relaxes the global threshold one level".to_string()),
                    secondary: false,
                },
                InterruptOption {
                    id: ID_INJECTION_EDIT.to_string(),
                    label: "Approve & edit the injection-check prompt".to_string(),
                    description: Some("you'll type a new check-prompt next".to_string()),
                    secondary: false,
                },
            ],
            allow_freetext: false,
            command_detail: None,
            // A genuine decision prompt (distinct action choices), not a
            // tool-permission scope select — keep the question presentation.
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let set = InterruptQuestionSet {
            questions: vec![question],
        };

        let choice = self.raise_and_wait(&agent, &description, set).await?;
        let id = selected_id_of(&choice);
        match id.as_deref() {
            Some(ID_INJECTION_SEND_ONCE) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "prompt-injection block overridden (sent once)".to_string(),
                    })
                    .await;
                Ok(true)
            }
            Some(ID_INJECTION_LOWER) => {
                let msg = match self.lower_injection_threshold() {
                    Ok(new) => format!(
                        "prompt-injection block overridden; threshold lowered to `{}`",
                        new.as_str()
                    ),
                    Err(e) => format!(
                        "prompt-injection block overridden (sent once); lowering threshold \
                         failed: {e}"
                    ),
                };
                let _ = tx.send(TurnEvent::Notice { text: msg }).await;
                Ok(true)
            }
            Some(ID_INJECTION_EDIT) => {
                // Follow-up free-text interrupt for the new check-prompt.
                let edit_set = InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Freetext {
                        prompt:
                            "Enter the new injection-check prompt (blank keeps the current one)"
                                .to_string(),
                        masked: false,
                    }],
                };
                let resp = self
                    .raise_and_wait(&agent, "Edit the injection-check prompt", edit_set)
                    .await?;
                let new_prompt = freetext_of(&resp);
                let msg = match new_prompt {
                    Some(text) if !text.trim().is_empty() => {
                        match self.write_injection_check_prompt(&text) {
                            Ok(scope) => format!(
                                "prompt-injection block overridden; check-prompt updated ({scope})"
                            ),
                            Err(e) => format!(
                                "prompt-injection block overridden (sent once); saving the \
                                 check-prompt failed: {e}"
                            ),
                        }
                    }
                    _ => "prompt-injection block overridden (sent once); check-prompt unchanged"
                        .to_string(),
                };
                let _ = tx.send(TurnEvent::Notice { text: msg }).await;
                Ok(true)
            }
            _ => {
                // Dismissed → the block stands.
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "prompt-injection block kept — prompt dropped".to_string(),
                    })
                    .await;
                Ok(false)
            }
        }
    }
}
