use super::*;

impl App {
    fn apply_launch_bundle(
        &mut self,
        mut fresh: LaunchInfo,
        providers: cockpit_config::providers::ProvidersConfig,
        extended: &cockpit_config::extended::ExtendedConfig,
    ) {
        // Don't clobber the live repo status — it's maintained by the
        // background poller and is fresher than a re-read here.
        fresh.repo_status = self.launch.repo_status.clone();
        if let Some(active_agent) = self.agent_path.last() {
            fresh.agent_name = active_agent.clone();
        }
        self.llm_mode =
            resolve_tui_llm_mode(fresh.active_model.as_ref(), extended.llm_mode, &providers);
        self.launch = fresh;
    }

    /// Re-read launch info (provider/model/favorite) from disk and
    /// keep the cwd + repo_status we already have.
    pub(super) fn reload_launch_info(&mut self) {
        // Skip the synchronous git fetch: the freshly-loaded `repo_status`
        // is discarded below in favor of the live polled one, so re-running
        // `git status` here is pure waste.
        let LaunchBundle {
            launch: fresh,
            providers,
            extended,
        } = welcome::load_bundle(Some(&self.launch.cwd), false);
        self.apply_launch_bundle(fresh, providers, &extended);
    }

    /// Re-read launch and TUI config from a single extended-config load.
    pub(super) fn reload_launch_and_tui_config(&mut self) {
        let LaunchBundle {
            launch: fresh,
            providers,
            extended,
        } = welcome::load_bundle(Some(&self.launch.cwd), false);
        self.apply_launch_bundle(fresh, providers, &extended);
        self.apply_tui_config_from_extended(&extended);
    }

    /// Re-read the TUI-side config (vim mode, thinking display,
    /// markdown rendering) so changes made via `/settings` take effect
    /// immediately on dialog close.
    pub(super) fn reload_tui_config(&mut self) {
        let extended = cockpit_config::extended::load_for_cwd(&self.launch.cwd);
        self.apply_tui_config_from_extended(&extended);
    }

    fn apply_tui_config_from_extended(
        &mut self,
        extended: &cockpit_config::extended::ExtendedConfig,
    ) {
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
        self.use_emojis = tui_cfg.use_emojis;
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
