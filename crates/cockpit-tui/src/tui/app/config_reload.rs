use super::*;

impl App {
    fn apply_launch_bundle(&mut self, mut fresh: LaunchInfo) {
        // Don't clobber the live repo status — it's maintained by the
        // background poller and is fresher than a re-read here.
        fresh.repo_status = self.launch.repo_status.clone();
        if let Some(active_agent) = self.agent_path.last() {
            fresh.agent_name = active_agent.clone();
        }
        self.launch = fresh;
    }

    /// Re-sync config after a local write (`/settings` close, `/favorite`,
    /// workspace-trust grant, a config-touching terminal command, a session
    /// swap). The daemon is the sole resolver: when attached, ask it to
    /// re-resolve and let the resulting pushed [`ConfigSnapshot`] update the
    /// UI — the value we just wrote is **not** optimistically rendered
    /// (`tui-config-single-source`, matching `active-model-switch-transaction`).
    /// When detached the write still happened, so refresh the bootstrap
    /// snapshot once from disk (the single documented detached exception).
    ///
    /// When a dirty response-metrics tokenizer candidate exists, this sends
    /// exactly one RefreshConfig for that final candidate and arms
    /// confirmation pending state.
    pub(super) fn resync_config_after_local_write(&mut self) {
        if matches!(self.agent_runner.as_ref(), Some(Ok(_))) {
            let applied = if let Some(candidate) = self.dirty_response_metrics_tokenizer.take() {
                // Supersede any prior pending confirmation silently.
                if let Some(prev) = self.pending_tokenizer_confirm.take() {
                    let _ = prev.supersede();
                }
                let (session_id, attachment_epoch) = self
                    .agent_runner
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|runner| (runner.session_id(), runner.attachment_epoch()))
                    .unwrap_or((uuid::Uuid::nil(), 0));
                let confirm_id = uuid::Uuid::new_v4();
                self.pending_tokenizer_confirm = Some(TokenizerConfirmPending::new(
                    confirm_id,
                    session_id,
                    attachment_epoch,
                    candidate,
                    self.event_loop_monotonic_now,
                ));
                ControlApplied::ResponseMetricsTokenizer { confirm_id }
            } else {
                ControlApplied::None
            };
            self.send_daemon_request("/settings", cockpit_proto::Request::RefreshConfig, applied);
        } else {
            self.dirty_response_metrics_tokenizer = None;
            self.refresh_bootstrap_config_snapshot();
        }
    }

    /// Apply a tokenizer confirmation outcome; append the durable post-dialog
    /// error exactly once on terminal failure.
    pub(super) fn apply_tokenizer_confirm_outcome(&mut self, outcome: TokenizerConfirmOutcome) {
        match outcome {
            TokenizerConfirmOutcome::Pending(p) => {
                self.pending_tokenizer_confirm = Some(p);
            }
            TokenizerConfirmOutcome::Confirmed | TokenizerConfirmOutcome::Cancelled => {
                self.pending_tokenizer_confirm = None;
            }
            TokenizerConfirmOutcome::Failed(failure) => {
                self.pending_tokenizer_confirm = None;
                self.history.push(HistoryEntry::CommandError {
                    line: failure.error_line(),
                });
            }
        }
    }

    /// Note a Behavior-page edit of the response metrics tokenizer so
    /// settings close sends one correlated refresh for the final candidate.
    pub(super) fn note_response_metrics_tokenizer_dirty(
        &mut self,
        candidate: cockpit_tokenizer::TiktokenEncoding,
    ) {
        self.dirty_response_metrics_tokenizer = Some(candidate);
    }

    /// Capture a dirty response-metrics tokenizer candidate from the open
    /// settings dialog before it is cleared on close.
    pub(super) fn capture_response_metrics_tokenizer_dirty_from_dialog(&mut self) {
        let Some(candidate) = self.dialog.response_metrics_tokenizer() else {
            return;
        };
        if candidate != self.config_snapshot.extended.response_metrics_tokenizer {
            self.note_response_metrics_tokenizer_dirty(candidate);
        }
    }

    /// Re-run the pre-attach bootstrap projection (extended read + redacted,
    /// credential-free provider view) and re-derive launch + TUI chrome from
    /// it. This is the one sanctioned client-side resolution, reused for the
    /// detached case (pre-attach first-run, unavailable-daemon `/settings` save).
    pub(super) fn refresh_bootstrap_config_snapshot(&mut self) {
        let LaunchBundle {
            launch: fresh,
            providers,
            extended,
        } = welcome::load_bundle_bootstrap_redacted(Some(&self.launch.cwd), false);
        self.config_snapshot = HeldConfig::from_view(
            self.config_snapshot.generation,
            false,
            extended.clone(),
            cockpit_core::secret_ref::redact_provider_view(&providers),
        );
        self.has_no_providers_at_startup = self.config_snapshot.providers.providers.is_empty();
        self.apply_launch_bundle(fresh);
        self.apply_tui_config_from_extended(&extended);
    }

    /// Apply TUI-side settings (vim mode, thinking display, markdown
    /// rendering, …) from the held config snapshot so a `/settings` change
    /// takes effect without a restart. Reads the held snapshot — never disk.
    pub(super) fn apply_tui_config_from_snapshot(&mut self) {
        let extended = self.config_snapshot.extended.clone();
        self.apply_tui_config_from_extended(&extended);
    }

    fn apply_tui_config_from_extended(
        &mut self,
        extended: &cockpit_config::extended::ExtendedConfig,
    ) {
        // This controls acquisition rather than rendering, but it must follow
        // the same authoritative snapshot as the Settings UI so the next
        // owner acquisition uses the current global preference.
        self.ephemeral_preference = !extended.daemon.background_agents;
        self.lifecycle.set_default_intent(self.lifecycle_intent());
        let tui_cfg = extended.tui.clone();
        self.vim_setting = tui_cfg.vim_mode;
        self.thinking_setting = tui_cfg.thinking;
        self.markdown_opts = MarkdownOpts {
            agent: tui_cfg.render_agent_markdown,
            user: tui_cfg.render_user_markdown,
        };
        self.diff_style = tui_cfg.diff_style;
        self.exit_tail_lines = tui_cfg.exit_tail_lines;
        self.rich_text_copy = tui_cfg.rich_text_copy;
        self.sticky_user_message = tui_cfg.sticky_user_message;
        self.clipboard_recovery = tui_cfg.clipboard_recovery;
        self.use_emojis = tui_cfg.use_emojis;
        self.file_icons = crate::tui::file_icons::file_icons_resolved(tui_cfg.file_icons);
        // Attention notification settings (implementation note):
        // pick up a `/settings` change so it takes effect immediately. The
        // debounce state intentionally survives — toggling the setting
        // shouldn't reset the burst-suppression window.
        self.attention = tui_cfg.attention;
        // The predict-next-message setting lives at the extended-config
        // root (not in `tui`); reload it so a `/settings` change takes
        // effect on subsequent turns. Turning it `off` also drops any
        // pending ghost/cache immediately.
        let predict_setting = extended.predict_next_message;
        self.predict_setting = predict_setting;
        if !predict_setting.is_enabled() {
            self.prediction_state.clear();
        }
        // Note: mouse_capture is *not* synced here. The live terminal
        // state is reconciled via the dialog's pending-flag drain
        // (see sync_mouse_capture_from_dialog) so we don't reapply
        // EnableMouseCapture on every reload — only when the user
        // actually toggled the setting.
        let vim_enabled = self.vim_setting.vim_enabled();
        if self.composer.vim_enabled() != vim_enabled {
            self.composer.set_vim_enabled(vim_enabled);
            // Mode stays whatever the composer was in; if vim flipped
            // off the composer will treat further input as Insert.
        }
    }
}
