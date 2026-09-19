use super::*;
use crate::tui::async_action::AsyncActionKind;
use crate::tui::session_rail::RailOutcome;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl App {
    pub(super) fn is_session_rail_focus_chord(key: &KeyEvent) -> bool {
        key.modifiers.contains(KeyModifiers::CONTROL)
            && !key
                .modifiers
                .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Char('j') | KeyCode::Char('J'))
    }

    pub(super) fn focus_session_rail_search(&mut self) {
        let worktree = self.resolved_worktree_root();
        self.session_rail
            .set_project_scope(worktree.as_deref(), &self.launch.cwd);
        if self.session_rail.set_daemon_connected(
            self.sessions_daemon_endpoint().is_some() || self.sessions_daemon_socket().is_some(),
        ) {
            self.abort_session_rail_runner_actions(false);
        }
        self.session_rail
            .set_use_emojis(self.config_snapshot.extended.tui.use_emojis);
        self.session_rail.focus_search();
        if self.session_rail.needs_initial_list() || self.session_rail.daemon_connected() {
            self.start_sessions_list_action();
        }
    }

    pub(super) fn maybe_start_session_rail_list(&mut self) {
        if !self.first_paint_completed {
            return;
        }
        let connected =
            self.sessions_daemon_endpoint().is_some() || self.sessions_daemon_socket().is_some();
        if self.session_rail.set_daemon_connected(connected) {
            self.abort_session_rail_runner_actions(false);
        }
        if connected && self.session_rail.needs_initial_list() {
            self.start_sessions_list_action();
        }
    }

    pub(super) fn invalidate_session_rail_for_reconnect(&mut self) {
        self.session_rail.set_daemon_connected(true);
        self.session_rail.invalidate_for_reconnect();
        self.abort_session_rail_runner_actions(true);
        if self.first_paint_completed {
            self.start_sessions_list_action();
        }
    }

    /// Abort in-flight rail RPCs. Projection reads always abort. Write RPCs
    /// (favorite and archive/delete/unarchive) abort only on reconnect or
    /// attachment epoch change so a disconnect can still settle a paired
    /// intent.
    pub(super) fn abort_session_rail_runner_actions(&mut self, include_writes: bool) {
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.list"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.live"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.preview"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.inbox"));
        if include_writes {
            self.async_actions
                .abort_kind(&AsyncActionKind::DaemonRpc("sessions.favorite"));
            self.async_actions
                .abort_kind(&AsyncActionKind::DaemonRpc("sessions.mutation"));
        }
    }

    pub(super) fn apply_session_rail_outcome(&mut self, outcome: Option<RailOutcome>) -> bool {
        match outcome {
            None => false,
            Some(RailOutcome::Unfocus) => true,
            Some(RailOutcome::ToggleVisibility) => {
                self.toggle_session_sidebar_from_chord();
                true
            }
            Some(RailOutcome::NewSession) => {
                self.pending_new_session = true;
                true
            }
            Some(RailOutcome::Resume(session_id)) => {
                self.resume_session(session_id);
                true
            }
            Some(RailOutcome::LoadList) => {
                self.start_sessions_list_action();
                true
            }
            Some(RailOutcome::LoadPreview {
                session_id,
                before_seq,
            }) => {
                self.start_sessions_preview_action(session_id, before_seq);
                true
            }
            Some(RailOutcome::LoadInbox { main_session_id }) => {
                self.start_sessions_inbox_action(main_session_id);
                true
            }
            Some(RailOutcome::Mutate(request)) => {
                self.start_sessions_mutation_action(*request);
                true
            }
            Some(RailOutcome::SetFavorite {
                session_id,
                favorite,
                canonical_root,
            }) => {
                self.start_sessions_favorite_action(session_id, favorite, canonical_root);
                true
            }
        }
    }

    pub(super) fn handle_session_rail_key(&mut self, key: KeyEvent) -> bool {
        if !self.session_rail.is_focused() {
            return false;
        }
        let outcome = self.session_rail.handle_key(key);
        self.apply_session_rail_outcome(outcome);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::session_rail::{
        COMPACT_AFFORDANCE_WIDTH, COMPACT_BREAKPOINT, RailLayoutMode, WIDE_BREAKPOINT,
    };
    use cockpit_proto::SessionSummary;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::{Terminal, backend::TestBackend};
    use uuid::Uuid;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn configured_app(tmp: &tempfile::TempDir) -> App {
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"active_model":{"provider":"p","model":"m"}}"#,
        )
        .unwrap();
        let provider_dir = cockpit.join("providers");
        std::fs::create_dir_all(&provider_dir).unwrap();
        std::fs::write(
            provider_dir.join("p.json"),
            r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
        )
        .unwrap();
        cockpit_config::trust::with_workspace_trust_policy(
            super::super::trusted_workspace_policy_for_tests(tmp.path()),
            || App::new(Some(tmp.path()), false),
        )
    }

    fn summary(id: Uuid, last_active: i64) -> SessionSummary {
        SessionSummary {
            session_id: id,
            session_entry_mode: "code".into(),
            short_id: Some("abc123".into()),
            project_root: "/proj/alpha".into(),
            project_id: "pid".into(),
            started_at_unix_ms: 0,
            last_active_at_unix_ms: last_active,
            turns: 0,
            active_agent: "builder".into(),
            title: Some(format!("session-{id}")),
            description: None,
            parent_session_id: None,
            fork_point_turn_id: None,
            is_assistant_thread: false,
            fork_count: 0,
            descendant_count: 0,
            last_viewed_at_unix_ms: None,
            latest_activity_at_unix_ms: None,
            open_interrupts: 0,
            activity_state: None,
            archived_at_unix_ms: None,
            favorite: false,
            created_by_principal: None,
            shared_with_collaborators: false,
            pin_count: 0,
            assistant_inbox_unread: 0,
            assistant_inbox_latest_source_session_id: None,
            compaction_predecessor_session_id: None,
            compaction_lineage_root_id: None,
            lineage_window_count: 1,
        }
    }

    fn seed_rail_sessions(app: &mut App, sessions: Vec<SessionSummary>) {
        app.session_rail.set_daemon_connected(true);
        assert!(app.session_rail.begin_list());
        let generation = app.session_rail.list_generation();
        let attachment = app.session_rail.attachment_generation();
        app.session_rail
            .apply_sessions_result(generation, attachment, Ok(sessions));
    }

    fn render_width(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect()
    }

    #[test]
    fn named_shell_widths_80_79_56_55() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.first_paint_completed = true;

        let text80 = render_width(&mut app, 80, 24);
        assert!(
            app.session_rail.rail_area().is_some() || text80.contains("sessions"),
            "80 columns must keep a persistent rail"
        );
        assert!(matches!(
            RailLayoutMode::from_width(80),
            RailLayoutMode::Wide { .. }
        ));
        assert_eq!(WIDE_BREAKPOINT, 80);
        assert_eq!(COMPACT_BREAKPOINT, 56);

        render_width(&mut app, 79, 24);
        let compact = app.session_rail.compact_area();
        assert!(
            compact.is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
                || app
                    .session_rail
                    .rail_area()
                    .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH),
            "79 columns must hide cards and show a compact affordance"
        );

        render_width(&mut app, 56, 24);
        assert!(
            app.session_rail
                .compact_area()
                .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
                || app
                    .session_rail
                    .rail_area()
                    .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
        );

        render_width(&mut app, 55, 24);
        assert!(app.session_rail.rail_area().is_none());
        assert!(app.session_rail.compact_area().is_none());
        app.session_rail.focus();
        render_width(&mut app, 55, 24);
        assert!(
            app.session_rail.rail_area().is_some(),
            "55 columns shows an overlay-sized rail only while focused"
        );
    }

    #[test]
    fn sessions_command_focuses_rail_search() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        assert!(!app.session_rail.is_focused());
        let cmd = *super::super::slash::SLASH_COMMANDS
            .iter()
            .find(|command| command.name == "sessions")
            .expect("/sessions");
        app.execute_slash(cmd);
        assert!(app.session_rail.is_focused());
        assert!(app.session_rail.is_search_focused());
        assert!(!app.overlay.is_open());
    }

    #[test]
    fn persistent_rail_remains_visible_under_owned_popover_surfaces() {
        let tmp = tempfile::tempdir().unwrap();

        let mut tools = configured_app(&tmp);
        let command = *super::super::slash::SLASH_COMMANDS
            .iter()
            .find(|command| command.name == "tools")
            .unwrap();
        tools.execute_slash(command);
        assert!(matches!(tools.overlay, Overlay::Tools(_)));
        render_width(&mut tools, 120, 40);
        assert!(tools.session_rail.rail_area().is_some());

        let mut settings = configured_app(&tmp);
        settings.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
            tmp.path().join("config.json"),
        )));
        render_width(&mut settings, 120, 40);
        assert!(settings.session_rail.rail_area().is_some());

        let mut picker = configured_app(&tmp);
        picker.open_model_picker();
        assert!(matches!(picker.overlay, Overlay::ModelPicker(_)));
        render_width(&mut picker, 120, 40);
        assert!(picker.session_rail.rail_area().is_some());

        let mut trust = configured_app(&tmp);
        trust.dialog = Dialog::open_workspace_trust(cockpit_config::trust::TrustRoot {
            opened_path: tmp.path().to_path_buf(),
            root: tmp.path().to_path_buf(),
            kind: cockpit_config::trust::TrustRootKind::Directory,
        });
        render_width(&mut trust, 120, 40);
        assert!(trust.session_rail.rail_area().is_some());
    }

    #[test]
    fn ctrl_j_focuses_rail_and_escape_returns_to_composer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.composer.insert_str("hello");
        app.handle_key(ctrl('j'));
        assert!(app.session_rail.is_focused());
        assert_eq!(app.composer.text(), "hello");
        app.handle_key(press(KeyCode::Esc));
        assert!(!app.session_rail.is_focused());
        app.handle_key(press(KeyCode::Char('!')));
        assert_eq!(app.composer.text(), "hello!");
    }

    #[test]
    fn alt_arrows_cycle_sessions_without_leaving_rail_focus() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        assert_eq!(app.session_rail.selected_id(), Some(first));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));
        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(!app.session_rail.is_focused());

        app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::ALT));
        assert_eq!(app.session_rail.selected_id(), Some(first));
        assert!(!app.session_rail.is_focused());

        // The chord's implicit Enter must actually resume the cycled-to
        // session, not just move the rail selection: with the live-switch
        // seam installed, Alt+↓ leaves a pending resume of `second`.
        let (_outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let mut runner = crate::tui::agent_runner::AgentRunner::test_fixture(Default::default());
        runner.install_live_swappable_switch_seam(outcome_rx);
        app.agent_runner = Some(Ok(runner));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(
            matches!(
                app.pending_session_switch_target,
                Some(crate::tui::agent_runner::SessionTarget::Resume {
                    session_id, ..
                }) if session_id == second
            ),
            "Alt+↓ must leave a pending resume of the cycled-to session"
        );
    }

    #[test]
    fn ctrl_b_visibility_survives_a_config_backed_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = configured_app(&tmp);
        assert!(first.session_rail.is_visible());
        first.handle_key(ctrl('b'));
        assert!(!first.session_rail.is_visible());
        assert!(!first.config_snapshot.extended.tui.session_rail_visible);

        let persisted = first.config_snapshot.extended.clone();
        let mut restarted = configured_app(&tmp);
        restarted.config_snapshot.extended = persisted;
        restarted.apply_tui_config_from_snapshot();
        assert!(
            !restarted.session_rail.is_visible(),
            "a fresh app applies the persisted per-user TUI preference"
        );

        restarted.handle_key(ctrl('b'));
        assert!(restarted.session_rail.is_visible());
        assert!(restarted.config_snapshot.extended.tui.session_rail_visible);
    }

    #[test]
    fn alt_arrows_switch_sessions_while_an_overlay_pane_is_open() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        // Open a real overlay pane through the router (which-key →
        // scratchpad) so the pane's own modal key handling is in the way.
        app.handle_key(ctrl('k'));
        app.handle_key(press(KeyCode::Char('n')));
        assert!(matches!(app.overlay, Overlay::Notes(_)));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(
            app.session_rail.selected_id(),
            Some(second),
            "Alt+↓ must switch sessions underneath an open overlay pane (excoc tui.rs:189-201)"
        );
        assert!(
            matches!(app.overlay, Overlay::Notes(_)),
            "the session chord does not dismiss the pane"
        );
    }

    #[test]
    fn alt_down_switches_sessions_while_a_composer_picker_is_open() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        let (_outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let mut runner = crate::tui::agent_runner::AgentRunner::test_fixture(Default::default());
        runner.install_live_swappable_switch_seam(outcome_rx);
        app.agent_runner = Some(Ok(runner));

        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert!(
            app.composer_controls.picker.is_some(),
            "Ctrl+P opens the model picker before the session chord"
        );

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(
            matches!(
                app.pending_session_switch_target,
                Some(crate::tui::agent_runner::SessionTarget::Resume {
                    session_id, ..
                }) if session_id == second
            ),
            "Alt+down must resume the next session instead of navigating the picker"
        );
        assert!(
            app.composer_controls.picker.is_none(),
            "the global session chord dismisses the picker as it falls through"
        );
        assert_eq!(
            app.composer_controls.selection, None,
            "dismissal releases composer-control ownership"
        );
    }

    #[test]
    fn rail_shortcuts_do_not_steal_composer_when_unfocused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Char('b')));
        assert_eq!(app.composer.text(), "ab");
        assert!(!app.session_rail.is_focused());
    }

    #[test]
    fn startup_does_not_issue_a_list_before_first_paint() {
        let tmp = tempfile::tempdir().unwrap();
        let app = configured_app(&tmp);
        assert!(!app.first_paint_completed);
        assert_eq!(app.session_rail.request_counts().list_started, 0);
        assert!(app.session_rail.needs_initial_list() || !app.session_rail.daemon_connected());
    }

    #[test]
    fn no_overlay_sessions_variant_in_production_enum() {
        let tmp = tempfile::tempdir().unwrap();
        let app = configured_app(&tmp);
        assert!(matches!(app.overlay, Overlay::None));
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tui/app/mod.rs"));
        assert!(
            !source.contains("Sessions(crate::tui::sessions_pane::SessionsPane)"),
            "Overlay::Sessions production variant must be removed"
        );
    }

    #[test]
    fn churn_counts_one_list_through_startup_resize_search_reconnect() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.first_paint_completed = true;
        app.session_rail.set_daemon_connected(true);
        app.start_sessions_list_action();
        app.start_sessions_list_action();
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);
        assert_eq!(app.session_rail.request_counts().list_started, 2);

        render_width(&mut app, 80, 24);
        render_width(&mut app, 100, 24);
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);

        let stale_list = app.session_rail.list_generation();
        let attach = app.session_rail.attachment_generation();
        app.session_rail.focus();
        app.session_rail.handle_key(press(KeyCode::Char('/')));
        app.session_rail.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.session_rail.request_counts().list_in_flight, 0);
        app.session_rail
            .apply_sessions_result(stale_list, attach, Ok(vec![]));
        assert_eq!(app.session_rail.request_counts().list_in_flight, 0);
        app.session_rail.handle_key(press(KeyCode::Esc));
        app.session_rail.handle_key(press(KeyCode::Esc));

        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        app.session_rail.focus();
        let started = app.session_rail.begin_preview(None).expect("preview");
        assert_eq!(started.0, first);
        app.start_sessions_preview_action(started.0, started.1);
        let stale_preview_gen = app.session_rail.list_generation();
        let stale_preview_attach = app.session_rail.attachment_generation();
        app.handle_session_rail_key(press(KeyCode::Down));
        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert_eq!(app.session_rail.request_counts().preview_in_flight, 1);
        assert_eq!(
            app.async_actions
                .pending_kinds()
                .into_iter()
                .filter(|kind| kind == &AsyncActionKind::DaemonRpc("sessions.preview"))
                .count(),
            1
        );
        app.session_rail.apply_preview_result(
            stale_preview_gen,
            stale_preview_attach,
            first,
            None,
            Ok((Vec::new(), false)),
        );
        assert_eq!(
            app.session_rail.request_counts().preview_in_flight,
            1,
            "stale preview for the previous selection must not consume the replacement in-flight slot"
        );
        assert_eq!(app.session_rail.preview_session_id(), Some(second));
        assert_eq!(app.session_rail.preview_message_count(), 0);

        app.session_rail.set_daemon_connected(true);
        assert!(app.session_rail.begin_list());
        let pre_reconnect_gen = app.session_rail.list_generation();
        let pre_reconnect_attach = app.session_rail.attachment_generation();
        app.invalidate_session_rail_for_reconnect();
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);
        app.session_rail
            .apply_sessions_result(pre_reconnect_gen, pre_reconnect_attach, Ok(vec![]));
        assert_ne!(app.session_rail.list_generation(), pre_reconnect_gen);
        assert!(app.session_rail.request_counts().list_in_flight <= 1);
        assert!(app.session_rail.request_counts().live_in_flight <= 1);
        assert!(app.session_rail.request_counts().preview_in_flight <= 1);
        assert!(app.session_rail.request_counts().favorite_in_flight <= 1);
    }

    #[test]
    fn reconnect_aborts_pending_session_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.first_paint_completed = true;
        seed_rail_sessions(&mut app, vec![summary(Uuid::from_u128(1), 10)]);
        app.session_rail.focus();
        app.handle_session_rail_key(press(KeyCode::Char('d')));
        app.handle_session_rail_key(press(KeyCode::Right));
        app.handle_session_rail_key(press(KeyCode::Enter));
        assert!(app.session_rail.has_unsettled_local_authority());
        assert!(
            app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
        app.invalidate_session_rail_for_reconnect();
        assert!(!app.session_rail.has_unsettled_local_authority());
        assert!(
            !app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
    }

    #[test]
    fn attachment_change_aborts_pending_session_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.first_paint_completed = true;
        seed_rail_sessions(&mut app, vec![summary(Uuid::from_u128(1), 10)]);
        app.session_rail.focus();
        app.handle_session_rail_key(press(KeyCode::Char('d')));
        app.handle_session_rail_key(press(KeyCode::Right));
        app.handle_session_rail_key(press(KeyCode::Enter));
        assert!(app.session_rail.has_unsettled_local_authority());
        assert!(
            app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
        app.session_rail.discard_for_attachment_change();
        app.abort_session_rail_runner_actions(true);
        assert!(!app.session_rail.has_unsettled_local_authority());
        assert!(
            !app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
    }

    #[test]
    fn overlay_rail_masks_transcript_hits() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        use ratatui::layout::Rect;

        let tmp = tempfile::tempdir().unwrap();
        let mut app = configured_app(&tmp);
        app.mouse_capture = true;
        app.session_rail.focus();
        render_width(&mut app, 55, 24);
        let rail = app.session_rail.rail_area().expect("focused overlay rail");
        let hidden = Rect {
            x: rail.x,
            y: rail.y.saturating_add(1),
            width: rail.width.clamp(1, 8),
            height: 1,
        };
        app.link_registry
            .register(hidden, "https://example.invalid/hidden", "hidden");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: hidden.x,
            row: hidden.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.pending_link_activation.is_none(),
            "hidden transcript links under the overlay rail must not activate"
        );
    }
}
