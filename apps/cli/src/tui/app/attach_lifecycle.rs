use super::*;

impl App {
    /// Attach the session eagerly once the daemon is reachable so the
    /// startup graphic can show its id (session-id-display-and-lazy-persist).
    /// The attach creates a deferred (un-persisted) session in the daemon;
    /// the first user message is what writes the `sessions` row. Runs each
    /// event-loop tick.
    ///
    /// Gates (all must hold):
    /// - No live runner yet. A successful attach (`Some(Ok)`) stops the
    ///   eager loop; a poisoned `Some(Err)` from a *previous first-message*
    ///   attempt would too, so this also short-circuits then — only the
    ///   `None` state retries here.
    /// - The "daemon not running" prompt is closed — we don't spawn a
    ///   daemon out from under the user's choice.
    /// - Not daemonless. In daemonless mode there is no daemon to merely
    ///   *show* an id for; eager-attaching would spawn the owned ephemeral
    ///   daemon purely for display. The short id appears once a daemon comes
    ///   up on its own (the first message). `daemon_connected` stays true in
    ///   that mode (the `/sessions` pane needs it), so it can't be the gate.
    /// - The canonical daemon probe is allowed to start. After "Start and
    ///   connect" the just-spawned socket isn't bound for a beat; probing in
    ///   the background lets us wait quietly and attach the instant it's up
    ///   without blocking this tick.
    pub(super) fn ensure_session_for_display(&mut self) {
        // Evaluate the cheap struct-only gates first; the daemon probe is the
        // only costly check, so only start it when everything else already
        // permits an attach (`probe_when` is lazy for exactly this reason).
        let should_probe = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemonless,
            self.daemon_connected,
            || true,
        );
        if should_probe && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.start_display_daemon_probe_action(|| crate::daemon::discover_blocking().status);
        }
    }

    pub(super) fn start_display_daemon_probe_action<F>(&mut self, work: F)
    where
        F: FnOnce() -> crate::daemon::DaemonStatus + Send + 'static,
    {
        let cwd = self.launch.cwd.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("display.daemon.probe"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("display.daemon.probe")),
            move || {
                Ok(AsyncActionPayload::DaemonProbe {
                    cwd,
                    status: work(),
                })
            },
        );
    }

    pub(super) fn apply_display_daemon_probe_result(
        &mut self,
        cwd: PathBuf,
        status: crate::daemon::DaemonStatus,
    ) {
        if cwd != self.launch.cwd {
            return;
        }
        if !matches!(status, crate::daemon::DaemonStatus::Running) {
            return;
        }
        let attach = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemonless,
            self.daemon_connected,
            || true,
        );
        if attach && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.try_attach_for_display();
        }
    }

    /// The daemon lifecycle this TUI attaches with. Daemonless mode owns a
    /// fresh pid+nonce ephemeral daemon (`AlwaysEphemeral`); otherwise the TUI
    /// attaches to the canonical daemon, auto-promoting a persistent one if
    /// none is running.
    pub(super) fn lifecycle_mode(&self) -> crate::daemon::client::LifecycleMode {
        if self.daemonless {
            // First attach spawns our owned pid+nonce ephemeral daemon; later
            // re-attaches (`/compact`, `/sessions` resume, `/new`) reconnect
            // to that same daemon instead of spawning a second one.
            crate::daemon::client::LifecycleMode::AttachOwnEphemeral
        } else {
            crate::daemon::client::LifecycleMode::AttachOrAutoPromote
        }
    }

    /// Build the ephemeral-daemon ownership guard (and arm its signal
    /// handler) for a runner that just spawned an owned daemon. No-op when
    /// the runner attached to a daemon we don't own or a guard already
    /// exists. The signal handler hands control back to the TUI's own
    /// restore path on SIGINT/SIGTERM rather than `exit`ing outright, so the
    /// alt-screen teardown still runs.
    pub(super) fn arm_daemon_guard(&mut self, runner: &AgentRunner) {
        if !runner.owns_daemon || self.daemon_guard.is_some() {
            return;
        }
        let guard =
            crate::daemon::ephemeral_guard::EphemeralDaemonGuard::new(runner.socket.clone());
        self.daemon_signal_task =
            crate::daemon::ephemeral_guard::spawn_signal_shutdown(Some(&guard), false);
        self.daemon_guard = Some(guard);
    }

    /// Spawn (or attach to) the daemon and **latch** the result —
    /// including a failure. The first-message path
    /// (`src/tui/app/input.rs`) calls this: a user-initiated submit must
    /// surface a spawn error in history, and storing `Some(Err)` keeps it
    /// visible. The opportunistic display attach uses
    /// [`Self::try_attach_for_display`] instead, which never latches an
    /// error.
    pub(super) fn ensure_agent_runner(&mut self) {
        if matches!(self.agent_runner, Some(Ok(_))) {
            return;
        }
        let runner =
            agent_runner::try_spawn(&self.launch.cwd, self.no_sandbox, self.lifecycle_mode());
        self.adopt_runner(runner);
    }

    /// Adopt a freshly-spawned runner: on success, record its identity
    /// (session id + short id for the startup graphic), seed the usage
    /// tallies, flush buffered usage records, and refresh the guidance
    /// estimate from the now-live daemon. Always stores the result (`Ok`
    /// or `Err`) so the caller's latch semantics hold. Shared by the
    /// first-message path and the eager display attach.
    pub(super) fn adopt_runner(&mut self, runner: Result<AgentRunner, String>) {
        if let Ok(r) = &runner {
            let live_btw_fork = r.btw_fork.clone();
            self.reset_display_attach_backoff();
            // In daemonless mode this runner spawned our own ephemeral
            // daemon; arm the ownership guard so it's reaped on exit.
            self.arm_daemon_guard(r);
            // Record the daemon-assigned session id so the startup graphic
            // shows it and `/new` re-renders with the fresh one
            // (session-id-display-and-lazy-persist).
            self.launch.session_id = Some(r.session_id);
            self.launch.session_short_id = Some(r.short_id.clone());
            // Seed the in-memory tally from the daemon's authoritative
            // counts. Additive: any optimistic increments made before
            // attach (held in the maps) stay on top of the historical
            // counts; the daemon's value isn't double-counted because we
            // only fetch once per session.
            merge_counts(&mut self.usage_models, &r.usage.models);
            merge_counts(&mut self.usage_slash, &r.usage.slash);
            merge_counts(&mut self.usage_tags, &r.usage.tags);
            self.project_id = Some(r.project_id.clone());
            self.foreground_input_target = r.foreground_target.clone();
            if let Some(state) = &r.active_model_state {
                self.apply_active_model_state(
                    state.provider.clone(),
                    state.model.clone(),
                    state.diverged,
                    state.generation,
                );
            }
            self.maybe_show_daemon_version_chip(&r.daemon_version, r.daemon_compatible);
            // Flush records buffered before the runner existed,
            // backfilling tag project ids now that we know the project.
            let pid = self.project_id.clone();
            for mut req in std::mem::take(&mut self.pending_usage) {
                if let crate::daemon::proto::Request::RecordUsage {
                    kind: crate::daemon::proto::UsageKind::Tag,
                    project_id,
                    ..
                } = &mut req
                    && project_id.is_none()
                {
                    *project_id = pid.clone();
                }
                let _ = r.record_tx.try_send(req);
            }
            // Refresh the fresh-chat guidance estimate from the daemon now
            // that one is guaranteed up (lazy spawn / attach just completed).
            // The launch-time figure was a local raw-cl100k fallback computed
            // before any daemon existed; the daemon answers with the active
            // model's calibrated tokenizer and the same file-resolution the
            // engine then injects, so the indicator matches what's actually
            // sent. Best-effort: a daemon that can't answer leaves the
            // launch-time estimate in place (no regression). Targets the
            // runner's own socket so it reaches an owned pid+nonce ephemeral
            // daemon (daemonless / auto-spawn), not just the canonical one —
            // reuses the just-established daemon, no new spawn, one request.
            self.refresh_guidance_estimate_from_daemon(&r.socket);
            if let Some(info) = live_btw_fork {
                self.open_btw_pane_from_info(info, true);
            }
        }
        let refresh_skills = runner.is_ok();
        self.agent_runner = Some(runner);
        if refresh_skills {
            self.refresh_skill_commands();
        }
    }

    /// Opportunistic display attach: attach a deferred session so the
    /// welcome box can show its short id before the first message, but —
    /// unlike [`Self::ensure_agent_runner`] — **never latch a failure**. A
    /// transient `try_spawn` error (e.g. the just-started daemon's socket
    /// isn't bound yet) leaves `agent_runner = None` so the next event-loop
    /// tick retries, rather than poisoning the runner to `Some(Err)` and
    /// permanently disabling the eager display. On success the runner is
    /// the same one the first-message path then reuses (it early-returns on
    /// `is_some()`), so the id shown in the welcome box is exactly the
    /// session persisted on first message.
    pub(super) fn try_attach_for_display(&mut self) {
        let runner =
            agent_runner::try_spawn(&self.launch.cwd, self.no_sandbox, self.lifecycle_mode());
        if runner.is_ok() {
            self.adopt_runner(runner);
        } else {
            self.display_attach_backoff.record_failure(Instant::now());
        }
        // On `Err`, drop it silently: leave `agent_runner` as `None` so a
        // later tick can retry once the daemon is actually reachable.
    }

    pub(super) fn reset_display_attach_backoff(&mut self) {
        self.display_attach_backoff.reset();
    }

    /// Re-fetch the fresh-chat guidance estimate from the daemon at `socket`
    /// (the attached runner's own socket) and adopt it when it carries a
    /// resolved file or a non-zero system-prompt size. Called once the lazy
    /// daemon spawn/attach completes so the indicator reflects the daemon's
    /// calibrated figure rather than staying stuck on the launch-time local
    /// fallback (which is computed before any daemon exists). A daemon that
    /// can't answer, or a degenerate all-zero/no-file reply, is ignored so a
    /// transient miss never blanks a correct local estimate. Touches only the
    /// indicator — never the cached system prompt — so the prompt cache is
    /// undisturbed.
    pub(super) fn refresh_guidance_estimate_from_daemon(&mut self, socket: &Path) {
        let (provider, model) = match &self.launch.active_model {
            Some((p, m)) => (Some(p.clone()), Some(m.clone())),
            None => (None, None),
        };
        let socket = socket.to_path_buf();
        let project_root = self.launch.cwd.to_string_lossy().into_owned();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("guidance.estimate"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("guidance.estimate")),
            move || {
                let resp = agent_runner::daemon_request_at_blocking(
                    &socket,
                    crate::daemon::proto::Request::GuidanceEstimate {
                        project_root,
                        provider,
                        model,
                    },
                )?;
                match resp {
                    crate::daemon::proto::Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                        model_instruction_tokens,
                    } if file.is_some() || system_tokens > 0 || model_instruction_tokens > 0 => Ok(
                        AsyncActionPayload::GuidanceEstimate(agent_runner::GuidanceEstimate {
                            file,
                            guidance_tokens: tokens,
                            system_tokens,
                            model_instruction_tokens,
                        }),
                    ),
                    _ => Err("empty guidance estimate".to_string()),
                }
            },
        );
    }

    /// Record one accepted autocomplete pick: bump the in-memory count
    /// optimistically (so the current session reflects it without a
    /// round-trip) and forward it to the daemon, buffering until the
    /// runner exists.
    pub(super) fn record_usage(
        &mut self,
        kind: crate::daemon::proto::UsageKind,
        key: String,
        project_id: Option<String>,
    ) {
        use crate::daemon::proto::UsageKind;
        let map = match kind {
            UsageKind::Model => &mut self.usage_models,
            UsageKind::Slash => &mut self.usage_slash,
            UsageKind::Tag => &mut self.usage_tags,
        };
        *map.entry(key.clone()).or_insert(0) += 1;
        let req = crate::daemon::proto::Request::RecordUsage {
            kind,
            key,
            project_id,
        };
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => {
                let _ = runner.record_tx.try_send(req);
            }
            _ => self.pending_usage.push(req),
        }
    }
}
