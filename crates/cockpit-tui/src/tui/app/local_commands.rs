use super::*;

impl App {
    pub(super) fn apply_local_command_result(
        &mut self,
        label: String,
        raw_output: String,
        failed: bool,
        git_args: Option<String>,
    ) {
        let clean = strip_ansi(&raw_output);
        self.history.push(HistoryEntry::LocalCommand {
            label,
            output: cap_display_lines(&clean),
            failed,
        });
        self.chat_scroll_offset = 0;
        if let Some(args) = git_args {
            let capped = cap_tokens(&clean, GIT_AGENT_TOKEN_CAP);
            self.pending_git_blocks.push(format!(
                "<git cmd=\"{}\">\n{}\n</git>",
                xml_escape(&args),
                capped
            ));
        }
    }

    /// Resolve a closed `/init` existing-file prompt. `selected_id` is the
    /// chosen option id (or `None` on Esc/cancel). Update/overwrite
    /// dispatch the corresponding agent turn; cancel leaves the file
    /// untouched.
    pub(super) fn resolve_init_choice(&mut self, pending: PendingInit, selected_id: Option<&str>) {
        let mode = match selected_id {
            Some("update") => cockpit_core::init::InitMode::Update,
            Some("overwrite") => cockpit_core::init::InitMode::Overwrite,
            _ => {
                self.push_plain(format!(
                    "/init: cancelled — `{}` left untouched",
                    pending.display
                ));
                return;
            }
        };
        let prompt = cockpit_core::init::build_init_prompt(&pending.display, mode);
        self.dispatch_init_turn(&pending.display, prompt);
    }

    pub(super) fn pending_local_choice_matches(&self, interrupt_id: uuid::Uuid) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(|choice| choice.interrupt_id() == interrupt_id)
    }

    pub(super) fn pending_local_choice_is_multi(&self) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(LocalChoice::is_multi)
    }

    pub(super) fn resolve_local_choice(&mut self, selection: LocalChoiceSelection) {
        match self.pending_local_choice.take() {
            Some(LocalChoice::Init(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_init_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::PausedWork(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_paused_work_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::ResumeRepair(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_resume_repair_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::RedactionToggle(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_redaction_toggle(selected.as_deref());
            }
            Some(LocalChoice::ModelComparison(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_model_comparison_select(selected.as_deref());
            }
            None => {}
        }
    }

    /// Send an `/init` turn to the agent: render `/init <target>` as the
    /// user's turn (display side) and hand the full exploration+write
    /// instruction to the agent as the wire (wire/user split, GOALS §14).
    /// Reuses the runner input channel `submit_input` uses, including the
    /// working-span bookkeeping so an orphaned dispatch never hangs the
    /// indicator.
    pub(super) fn dispatch_init_turn(&mut self, display: &str, wire: String) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = cockpit_core::engine::message::UserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/init {display}"),
            submission,
            "/init",
            true,
            &[],
        );
    }

    pub(super) fn dispatch_optimistic_user_submission(
        &mut self,
        display: String,
        mut submission: cockpit_core::engine::message::UserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[cockpit_core::daemon::proto::TagExpansionMeta],
    ) -> DispatchOutcome {
        if submission.display_text.is_none() && submission.text != display {
            submission.display_text = Some(display.clone());
        }
        if submission.tag_expansions.is_empty() && !tag_expansions.is_empty() {
            submission.tag_expansions = tag_expansions.to_vec();
        }
        self.lock_pending_agent_switch_log();
        self.history.push(HistoryEntry::User {
            text: display,
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_tag_call_entries(tag_expansions);
        self.ensure_agent_runner();
        let outcome = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => match runner.input_tx.try_send(submission) {
                Ok(_) => {
                    self.current_session_persisted = true;
                    if owns_working_span {
                        self.fresh_queue_ack = FreshQueueAck::AwaitingAck;
                    }
                    DispatchOutcome::Sent
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => DispatchOutcome::QueueFull,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    DispatchOutcome::DriverClosed
                }
            },
            Some(Err(_)) => DispatchOutcome::RunnerFailed,
            None => DispatchOutcome::NoRunner,
        };
        if outcome != DispatchOutcome::Sent {
            if owns_working_span {
                self.fresh_queue_ack = FreshQueueAck::None;
            }
            self.reconcile_failed_dispatch(outcome, error_prefix, tag_expansions.len());
        }
        if owns_working_span && outcome.span_orphaned() {
            self.end_working_span();
        }
        outcome
    }

    pub(super) fn reconcile_failed_dispatch(
        &mut self,
        outcome: DispatchOutcome,
        error_prefix: &str,
        optimistic_tag_entries: usize,
    ) {
        if let Some(idx) = self.history.iter().rposition(|entry| {
            matches!(
                entry,
                HistoryEntry::User {
                    seq: None,
                    persist_failed: false,
                    ..
                }
            )
        }) {
            for _ in 0..optimistic_tag_entries {
                if idx + 1 < self.history.len() {
                    self.history.remove(idx + 1);
                }
            }
            if let HistoryEntry::User {
                preflight_pending,
                persist_failed,
                ..
            } = &mut self.history[idx]
            {
                *preflight_pending = false;
                *persist_failed = true;
            }
        }
        self.history.push(HistoryEntry::CommandError {
            line: failed_dispatch_line(error_prefix, outcome),
        });
    }

    pub(super) fn resolve_paused_work_choice(
        &mut self,
        pending: PendingPausedWork,
        selected_id: Option<&str>,
    ) {
        let request = match selected_id {
            Some("resume") => {
                self.push_plain("/resume: resuming paused daemon work.".to_string());
                cockpit_core::daemon::proto::Request::ResumePausedWork {
                    session_id: pending.session_id,
                }
            }
            Some("cancel") | None => {
                self.push_plain("/resume: cancelled paused daemon work.".to_string());
                cockpit_core::daemon::proto::Request::CancelPausedWork {
                    session_id: pending.session_id,
                }
            }
            Some(_) => return,
        };
        self.send_daemon_request("/resume", request, ControlApplied::None);
    }

    pub(super) fn show_goal_status(&mut self) {
        let Some(session_id) = self.launch.session_id else {
            self.push_plain("/goal: no active session. Usage: /goal <objective> | status | pause | resume | clear | edit".to_string());
            return;
        };
        match cockpit_db::Db::open_default().and_then(|db| {
            db.refresh_session_goal_usage(session_id)?;
            db.current_session_goal(session_id, false)
        }) {
            Ok(Some(goal)) => {
                let budget = goal
                    .token_budget
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_string());
                self.push_plain(format!(
                        "/goal: {} · {} · tokens {}/{} · subcommands: status, pause, resume, clear, edit",
                        goal.status.as_str(),
                        goal.objective,
                        goal.tokens_used,
                        budget
                    ));
            }
            Ok(None) => self.push_plain(
                "/goal: no goal. Usage: /goal <objective> | status | pause | resume | clear | edit"
                    .to_string(),
            ),
            Err(e) => self.history.push(HistoryEntry::CommandError {
                line: format!("/goal: {e:#}"),
            }),
        }
    }

    pub(super) fn set_goal_status(
        &mut self,
        status: cockpit_db::session_goals::GoalStatus,
        label: &str,
    ) {
        let Some(session_id) = self.launch.session_id else {
            self.history.push(HistoryEntry::CommandError {
                line: format!("{label}: no active session."),
            });
            return;
        };
        match cockpit_db::Db::open_default()
            .and_then(|db| db.set_session_goal_status(session_id, status))
        {
            Ok(goal) => self.push_plain(format!("{label}: goal is now {}.", goal.status.as_str())),
            Err(e) => self.history.push(HistoryEntry::CommandError {
                line: format!("{label}: {e:#}"),
            }),
        }
    }

    pub(super) fn dispatch_goal_turn(&mut self, display: &str, wire: String) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = cockpit_core::engine::message::UserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/goal {display}"),
            submission,
            "/goal",
            true,
            &[],
        );
    }

    /// Dispatch a user-issued skill slash command
    /// (implementation note): seed a deterministic `skill`
    /// tool call for `name` before the turn's inference and forward `args`
    /// (possibly empty) as the accompanying task input.
    ///
    /// `display` is the user-facing turn label (`/<name> args` for the bare
    /// form, `/skill <name> args` for the dispatcher). The seed itself rides
    /// in `UserSubmission::forced_skill`, so the harness — not the model —
    /// loads the skill body (priority #1). Reuses the runner-input dispatch
    /// `dispatch_init_turn` uses, including the working-span bookkeeping.
    pub(super) fn dispatch_skill_invocation(&mut self, display: String, name: &str, args: &str) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = cockpit_core::engine::message::UserSubmission {
            kind: cockpit_core::engine::message::UserSubmissionKind::User,
            text: args.trim().to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: Some(name.to_string()),
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        };
        self.dispatch_optimistic_user_submission(display, submission, "/skill", true, &[]);
    }

    /// The id of the session this client is attached to (live runner if
    /// connected, else the last-attached id from launch info). `None`
    /// before the first session exists. Same resolution `/rename` uses.
    pub(super) fn current_session_id(&self) -> Option<uuid::Uuid> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id),
            _ => self.launch.session_id,
        }
    }

    /// Job ids in `active_schedules` that belong to the current session, in the
    /// map's (stable, job-id) order. The single filter `/ps` and `/stop`
    /// share so the listed set, the cancel set, and the confirm count can
    /// never disagree. Empty when there's no current session or no jobs.
    pub(super) fn current_session_job_ids(&self) -> Vec<String> {
        match self.current_session_id() {
            Some(sid) => session_schedule_ids(&self.active_schedules, sid),
            None => Vec::new(),
        }
    }

    /// Send a `CancelSchedule` for one job over the response-bearing control
    /// channel. `cmd` is the command label for the rendered line.
    pub(super) fn cancel_schedule(&mut self, job_id: &str, cmd: &str) {
        self.send_daemon_request(
            cmd,
            cockpit_core::daemon::proto::Request::CancelSchedule {
                job_id: job_id.to_string(),
            },
            ControlApplied::ScheduleCancel {
                command: cmd.to_string(),
                job_id: job_id.to_string(),
            },
        );
    }

    /// Bare `/stop`: count the current-session jobs and arm the `[y/N]`
    /// confirm (mirrors `/prune`'s arm-then-commit). With zero jobs it
    /// says so and arms nothing.
    pub(super) fn arm_stop_confirm(&mut self) {
        let ids = self.current_session_job_ids();
        if ids.is_empty() {
            self.push_plain("No background jobs in this session.".to_string());
            self.pending_stop_confirm = None;
            return;
        }
        let n = ids.len();
        self.push_plain(format!("/stop: Stop {n} job(s) in this session? [y/N]"));
        self.pending_stop_confirm = Some(ids);
    }

    /// Commit an armed bare `/stop`: cancel every job captured at arm
    /// time. A job that already ended (no longer in `active_schedules`) is
    /// skipped silently — its strip entry is already gone.
    pub(super) fn commit_stop(&mut self) {
        let Some(ids) = self.pending_stop_confirm.take() else {
            return;
        };
        let mut cancelled = 0;
        for job_id in ids {
            if self.active_schedules.contains_key(&job_id) {
                self.cancel_schedule(&job_id, "/stop");
                cancelled += 1;
            }
        }
        if cancelled == 0 {
            self.push_plain("/stop: those jobs already ended.".to_string());
        }
    }

    /// Cancel an armed bare `/stop`.
    pub(super) fn cancel_stop(&mut self) {
        self.pending_stop_confirm = None;
        self.push_plain("/stop: cancelled.".to_string());
    }

    /// Resolve the layered `mcp.json` path for the cwd (first discovered
    /// `.cockpit/`), preferring an existing file, else the first creatable.
    pub(super) fn mcp_config_path(&self) -> Option<std::path::PathBuf> {
        let cwd = &self.launch.cwd;
        for d in cockpit_config::dirs::discover_config_dirs(cwd) {
            let p = d.path.join("mcp.json");
            if p.exists() {
                return Some(p);
            }
        }
        cockpit_config::dirs::cwd_scoped_creatable_dirs(cwd)
            .into_iter()
            .next()
            .map(|d| d.path.join("mcp.json"))
    }

    pub(super) fn mcp_load(&self) -> cockpit_core::mcp::config::McpConfig {
        #[cfg(test)]
        MCP_LOAD_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        cockpit_core::mcp::config::McpConfig::discover(&self.launch.cwd)
    }

    pub(super) fn mcp_save(&mut self, cfg: &cockpit_core::mcp::config::McpConfig) -> bool {
        self.slash_menu_cache.borrow_mut().take();
        let Some(path) = self.mcp_config_path() else {
            self.push_plain("No writable .cockpit/ directory for MCP config".to_string());
            return false;
        };
        match cfg.write_private(&path) {
            Ok(_) => true,
            Err(_) => {
                self.push_plain("Failed to write mcp.json".to_string());
                false
            }
        }
    }

    pub(super) fn mcp_list(&mut self) {
        let cfg = self.mcp_load();
        if cfg.servers.is_empty() {
            self.push_plain("No MCP servers configured.".to_string());
            return;
        }
        for (name, s) in &cfg.servers {
            let color = crate::tui::settings::mcp_row_color(name, s);
            let dot = match color {
                ratatui::style::Color::Green => "●",
                ratatui::style::Color::Yellow => "○",
                _ => "✗",
            };
            self.push_plain(format!(
                "{dot} {name}  {}  {}  auth={}",
                s.transport.as_str(),
                if s.enabled { "enabled" } else { "disabled" },
                s.auth.kind_str(),
            ));
        }
    }

    /// `/mcp on|off|toggle [id]`. `enable=None` toggles; a mixed set toggled
    /// in bulk turns all **off** (spec). `id=None` applies to every server.
    pub(super) fn mcp_set_enabled(&mut self, id: Option<&str>, enable: Option<bool>) {
        let mut cfg = self.mcp_load();
        if let Some(id) = id {
            let Some(server) = cfg.servers.get_mut(id) else {
                self.push_plain(format!("Unknown MCP server `{id}`"));
                return;
            };
            server.enabled = enable.unwrap_or(!server.enabled);
        } else {
            let target = match enable {
                Some(v) => v,
                None => {
                    // Bulk toggle: if any is enabled (mixed/all-on), turn all
                    // off; only when all are off do we turn all on.
                    !cfg.servers.values().any(|s| s.enabled)
                }
            };
            for s in cfg.servers.values_mut() {
                s.enabled = target;
            }
        }
        if self.mcp_save(&cfg) {
            self.mcp_list();
        }
    }

    /// Shared cache-break warning helper. Returns the one-line warning to
    /// show when an action busts the cached system prefix (a `/llm-mode`
    /// switch today; the shift+tab agent cycle and `/agent` — specced
    /// elsewhere — reuse this verbatim). Returns `None` when the warning is
    /// meaningless because the active model/provider does not cache: reuses
    /// the pruning-policy no-cache predicate
    /// ([`cockpit_core::engine::prune::cache_state`] →
    /// [`cockpit_core::engine::prune::ColdReason::NoCacheProvider`]) rather than
    /// re-deriving "does this provider cache."
    pub(super) fn cache_break_warning(&self) -> Option<String> {
        if self.active_provider_caches() {
            Some(
                "Heads up: switching busts the prompt cache — the next call re-sends the \
                 full prefix uncached."
                    .to_string(),
            )
        } else {
            // No-cache provider: nothing to bust, so no warning.
            None
        }
    }

    /// Whether the active model/provider has a prompt cache at all. Reuses
    /// the pruning-policy no-cache predicate: the resolved
    /// [`cockpit_config::providers::CacheConfig`] is fed to
    /// [`cockpit_core::engine::prune::cache_state`]; a `NoCacheProvider` cold reason
    /// means it never caches. Best-effort — an unresolvable model is treated
    /// as caching so the warning errs on the side of showing.
    pub(super) fn active_provider_caches(&self) -> bool {
        let Some((provider, model)) = self.launch.active_model.as_ref() else {
            return true;
        };
        let providers = cockpit_core::secret_ref::load_effective(&self.launch.cwd);
        let cache = providers.resolve_cache(provider, model);
        cache_config_caches(&cache)
    }

    /// Whether inline `<think>` stripping runs for the active session model,
    /// resolved through the three-tier toggle (model `inline_think` → provider
    /// `inline_think` → global `inlineThink`,
    /// implementation note). Loaded fresh from
    /// the layered config at each turn start so model swaps and `/settings`
    /// edits take effect on the next turn without a restart. An unresolvable
    /// model falls through to the global default (on).
    pub(super) fn strip_inline_think(&self) -> bool {
        let (extended, providers) = cockpit_core::auto_title::load_configs_for(&self.launch.cwd);
        match self.launch.active_model.as_ref() {
            Some((provider, model)) => {
                providers.resolve_inline_think(provider, model, extended.inline_think)
            }
            None => extended.inline_think,
        }
    }

    pub(super) fn pending_or_insert_with_strip<F>(
        &mut self,
        agent: String,
        resolve_strip: F,
    ) -> &mut PendingMsg
    where
        F: FnOnce(&Self) -> bool,
    {
        if self.pending.is_none() {
            let strip_think = resolve_strip(self);
            self.pending = Some(new_pending(agent, strip_think));
        }
        self.pending.as_mut().expect("pending initialized")
    }

    /// Bare-`/<skill-name>` sugar (implementation note):
    /// the composer holds `/<name>` optionally followed by trailing args. Seed
    /// a deterministic skill invocation, forwarding the trailing text as the
    /// task input. Tallies under the `/skill` dispatcher for frequency ranking
    /// (the bare names aren't builtins, so they share one counter). Always
    /// returns `false` (the TUI stays open).
    pub(super) fn invoke_skill_slash(&mut self, name: &str) -> bool {
        let raw = self.composer.text().to_string();
        let args = slash_args(&raw);
        self.composer.clear();
        self.paste_registry.clear();
        self.reset_slash_window();
        self.record_usage(
            cockpit_core::daemon::proto::UsageKind::Slash,
            "skill".to_string(),
            None,
        );
        let display = if args.trim().is_empty() {
            format!("/{name}")
        } else {
            format!("/{name} {}", args.trim())
        };
        self.dispatch_skill_invocation(display, name, &args);
        false
    }
}
