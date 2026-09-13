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

    pub(super) fn abort_session_rail_runner_actions(&mut self, include_favorites: bool) {
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.list"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.live"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.preview"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.inbox"));
        if include_favorites {
            self.async_actions
                .abort_kind(&AsyncActionKind::DaemonRpc("sessions.favorite"));
        }
    }

    pub(super) fn apply_session_rail_outcome(&mut self, outcome: Option<RailOutcome>) -> bool {
        match outcome {
            None => false,
            Some(RailOutcome::Unfocus) => true,
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
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::{Terminal, backend::TestBackend};

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
        std::fs::create_dir(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"active_model":{"provider":"p","model":"m"}}"#,
        )
        .unwrap();
        let provider_dir = cockpit.join("providers");
        std::fs::create_dir(&provider_dir).unwrap();
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
            width: rail.width.min(8).max(1),
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
